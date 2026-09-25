// Package serverapp configures database access, TLS and graceful HTTP shutdown.
package serverapp

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/api"
	"github.com/Dja-tiger/gophkeeper/internal/store"
)

// Run starts the server until ctx is canceled. DATABASE_URL is read through getenv.
// Plain HTTP requires --dev-http and a literal loopback listen address.
func Run(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	f := flag.NewFlagSet("gophkeeper-server", flag.ContinueOnError)
	f.SetOutput(out)
	address := f.String("listen", "127.0.0.1:8443", "listen address")
	cert := f.String("tls-cert", "", "TLS certificate PEM")
	key := f.String("tls-key", "", "TLS private key PEM")
	dev := f.Bool("dev-http", false, "allow HTTP on loopback")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	host, _, e := net.SplitHostPort(*address)
	if e != nil {
		return e
	}
	ip := net.ParseIP(host)
	if *dev && (ip == nil || !ip.IsLoopback()) {
		return errors.New("development HTTP must listen on a literal loopback address")
	}
	var certificates []tls.Certificate
	if !*dev {
		if *cert == "" || *key == "" {
			return errors.New("--tls-cert and --tls-key required")
		}
		pair, e := tls.LoadX509KeyPair(*cert, *key)
		if e != nil {
			return e
		}
		certificates = []tls.Certificate{pair}
	}
	dsn := getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL required")
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	db, e := store.New(startup, dsn)
	if e != nil {
		return errors.New("database connection failed")
	}
	defer db.Close()
	if e = db.Migrate(startup); e != nil {
		return errors.New("database migration failed")
	}
	listener, e := net.Listen("tcp", *address)
	if e != nil {
		return e
	}
	defer listener.Close()
	logger := slog.New(slog.NewJSONHandler(out, nil))
	maintenanceCtx, stopMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan struct{})
	go func() { defer close(maintenanceDone); cleanSessions(maintenanceCtx, db, logger, 5*time.Minute) }()
	defer func() { stopMaintenance(); <-maintenanceDone }()
	server := &http.Server{Handler: api.New(db, logger), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: certificates}}
	if !*dev {
		listener = tls.NewListener(listener, server.TLSConfig)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Fprintf(out, "Listening on %s\n", listener.Addr())
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		e = server.Shutdown(shutdown)
		if e != nil {
			_ = server.Close()
		}
		return e
	}
}

type sessionCleaner interface {
	DeleteExpiredSessions(context.Context, time.Time) error
}

func cleanSessions(ctx context.Context, db sessionCleaner, logger *slog.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		cleanup, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := db.DeleteExpiredSessions(cleanup, time.Now())
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "expired session cleanup failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
