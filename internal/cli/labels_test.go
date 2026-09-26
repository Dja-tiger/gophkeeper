package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/api"
	"github.com/Dja-tiger/gophkeeper/internal/client"
	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/testutil"
)

func TestCLIExplicitPublicLabels(t *testing.T) {
	server := httptest.NewServer(api.New(testutil.NewDB(), slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer server.Close()
	ctx := context.Background()
	r, err := client.NewRemote(server.URL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	salt, check, err := client.VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Register(ctx, model.Credentials{Login: "alice", Password: "authentication-123", Salt: salt, KeyCheck: check})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, master, input := filepath.Join(dir, "cache.json"), filepath.Join(dir, "master"), filepath.Join(dir, "secret.json")
	if err = client.NewCache(server.URL, session).Save(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(master, []byte("master-password-123"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, []byte(`{"type":"text","title":"note","text":"secret","metadata":"private"}`), 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(command string, args ...string) (string, error) {
		var out bytes.Buffer
		flags := []string{command, "--dev-http", "--cache", path, "--vault-password-file", master}
		flags = append(flags, args...)
		err := Run(ctx, flags, &out, io.Discard)
		return out.String(), err
	}
	out, err := invoke("add", "--input", input, "--labels", "work,personal")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(out)
	if _, err = invoke("add", "--input", input, "--offline"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err = invoke("list", "--label", "work")
	if err != nil || !strings.Contains(out, id) {
		t.Fatal(out, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("filtered snapshot overwrote full cache or pending data")
	}
	out, err = invoke("list", "--label", "work", "--offline")
	if err != nil || !strings.Contains(out, id) {
		t.Fatal(out, err)
	}
	if _, err = invoke("edit", "--id", id, "--input", input, "--labels", ""); err != nil {
		t.Fatal(err)
	}
	out, err = invoke("list", "--label", "work")
	if err != nil || out != "" {
		t.Fatal("clearing labels failed", out, err)
	}
	for _, args := range [][]string{{"--label", ""}, {"--labels", "work"}} {
		if _, err = invoke("list", args...); err == nil {
			t.Fatal("invalid flag accepted")
		}
	}
}
