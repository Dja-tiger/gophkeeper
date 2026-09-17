//go:build integration

package serverapp

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/client"
	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func TestTLSLifecycle(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("disposable database required")
	}
	template := httptest.NewTLSServer(nil)
	cert := template.TLS.Certificates[0]
	template.Close()
	key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, certificate, 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, []string{"--listen", "127.0.0.1:0", "--tls-cert", certPath, "--tls-key", keyPath}, func(string) string { return dsn }, writer)
		writer.Close()
	}()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(reader)
		if scanner.Scan() {
			ready <- strings.TrimPrefix(scanner.Text(), "Listening on ")
		}
	}()
	var address string
	select {
	case address = <-ready:
	case e := <-done:
		t.Fatal("server failed", e)
	case <-time.After(20 * time.Second):
		t.Fatal("startup timeout")
	}
	remote, e := client.NewRemote("https://"+address, false, certificate)
	if e != nil {
		t.Fatal(e)
	}
	login := "tls-" + vault.ID()
	salt, check, e := client.VaultParameters(login, "vault-password-test")
	if e != nil {
		t.Fatal(e)
	}
	s, e := remote.Register(ctx, model.Credentials{Login: login, Password: "authentication-test", Salt: salt, KeyCheck: check})
	if e != nil {
		t.Fatal(e)
	}
	remote.Token = s.Token
	if _, e = remote.List(ctx); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("shutdown", e)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown timeout")
	}
}
