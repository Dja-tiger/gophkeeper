package cli

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestWorkflow(t *testing.T) {
	server := httptest.NewServer(api.New(testutil.NewDB(), slog.Default()))
	defer server.Close()
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache.json")
	auth := filepath.Join(dir, "auth")
	master := filepath.Join(dir, "master")
	input := filepath.Join(dir, "input.json")
	os.WriteFile(auth, []byte("authentication-123\n"), 0600)
	os.WriteFile(master, []byte("master-password-123\n"), 0600)
	invoke := func(command string, args ...string) (string, error) {
		t.Helper()
		all := []string{command, "--cache", cache, "--dev-http", "--vault-password-file", master}
		all = append(all, args...)
		var out, errOut bytes.Buffer
		e := Run(context.Background(), all, &out, &errOut)
		return out.String(), e
	}
	if _, e := invoke("register", "--server", server.URL, "--login", "alice", "--auth-password-file", auth); e != nil {
		t.Fatal(e)
	}
	for _, s := range []model.Secret{{Type: "text", Title: "note", Text: "secret note", Metadata: "site"}, {Type: "credentials", Title: "account", Login: "user", Password: "secret"}, {Type: "card", Title: "bank", CardNumber: "1234", CardHolder: "Alice", Expiry: "12/30", CVV: "123"}, {Type: "binary", Title: "file", Filename: "sample.bin", Binary: []byte{0, 255, 42}}} {
		b, _ := json.Marshal(s)
		os.WriteFile(input, b, 0600)
		out, e := invoke("add", "--input", input)
		if e != nil {
			t.Fatal(e)
		}
		id := strings.TrimSpace(out)
		args := []string{"--id", id}
		if s.Type == "binary" {
			args = append(args, "--output", filepath.Join(dir, "download.bin"))
		}
		out, e = invoke("get", args...)
		if e != nil {
			t.Fatal(e)
		}
		if s.Type != "binary" && !strings.Contains(out, s.Title) {
			t.Fatal(out)
		}
		if s.Type == "text" {
			s.Text = "edited"
			b, _ = json.Marshal(s)
			os.WriteFile(input, b, 0600)
			if _, e = invoke("edit", "--id", id, "--input", input, "--offline"); e != nil {
				t.Fatal(e)
			}
			if _, e = invoke("sync"); e != nil {
				t.Fatal(e)
			}
		}
		if _, e = invoke("delete", "--id", id); e != nil {
			t.Fatal(e)
		}
	}
	if out, e := invoke("status"); e != nil || !strings.Contains(out, "alice") {
		t.Fatal(out, e)
	}
	if out, e := invoke("list", "--offline"); e != nil || out != "" {
		t.Fatal(out, e)
	}
	if _, e := invoke("logout"); e != nil {
		t.Fatal(e)
	}
	if _, e := invoke("sync"); e == nil {
		t.Fatal("logged out sync succeeded")
	}
	if _, e := invoke("login", "--server", server.URL, "--login", "alice", "--auth-password-file", auth); e != nil {
		t.Fatal(e)
	}
	if _, e := invoke("register", "--server", server.URL, "--login", "alice", "--auth-password-file", auth); e == nil {
		t.Fatal("overwrote existing cache")
	}
	c, e := client.Load(cache)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Pending) != 0 {
		t.Fatal("pending changes left")
	}
}
func TestCLIInputErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"version"}, {"--version"}} {
		var out bytes.Buffer
		if e := Run(context.Background(), args, &out, &out); e != nil || out.Len() == 0 {
			t.Fatal(args, e)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"get", "--unknown"}, {"get", "unexpected"}, {"register", "--login", "!"}, {"status", "--cache", filepath.Join(t.TempDir(), "missing")}} {
		var out bytes.Buffer
		if e := Run(context.Background(), args, &out, &out); e == nil {
			t.Fatal("accepted", args)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	os.WriteFile(path, []byte("abc"), 0600)
	if _, e := readLimited(path, 2); e == nil {
		t.Fatal("limit ignored")
	}
	if _, e := readPassword("/does-not-exist", "", &bytes.Buffer{}); e == nil {
		t.Fatal("missing password file")
	}
	if e := writeNew(path, []byte("overwrite")); e == nil {
		t.Fatal("overwrote existing file")
	}
	if _, e := remote("https://example.com", options{ca: "/missing"}); e == nil {
		t.Fatal("missing ca accepted")
	}
}
