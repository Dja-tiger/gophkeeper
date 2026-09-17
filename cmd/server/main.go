// Command server runs the GophKeeper HTTPS server backed by PostgreSQL.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Dja-tiger/gophkeeper/internal/serverapp"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := serverapp.Run(ctx, os.Args[1:], os.Getenv, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
