package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/client"
	"github.com/Dja-tiger/gophkeeper/internal/model"
)

func TestInputErrorsDoNotExposeSecrets(t *testing.T) {
	salt, check, err := client.VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, master, input := filepath.Join(dir, "cache.json"), filepath.Join(dir, "master"), filepath.Join(dir, "input.json")
	c := client.NewCache("https://example.com", model.Session{Login: "alice", Salt: salt, KeyCheck: check})
	if err = c.Save(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(master, []byte("master-password-123"), 0600); err != nil {
		t.Fatal(err)
	}
	const secret = "private-secret-must-not-leak"
	for _, body := range []string{`{"` + secret + `":"value"}`, `{"text":` + secret + `}`, `{"type":"card","card_number":12345678901234567890123456789012345678901234567890}`} {
		if err = os.WriteFile(input, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		err = Run(context.Background(), []string{"add", "--offline", "--cache", path, "--vault-password-file", master, "--input", input}, &out, &errOut)
		if err == nil {
			t.Fatal("invalid input accepted")
		}
		if strings.Contains(err.Error()+out.String()+errOut.String(), secret) {
			t.Fatal("secret leaked in error")
		}
	}
}

func TestLogoutPreservesDataAndClearsOnlyInvalidToken(t *testing.T) {
	salt, check, err := client.VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{200, 401, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		path := filepath.Join(t.TempDir(), "cache.json")
		c := client.NewCache(server.URL, model.Session{Login: "alice", Salt: salt, KeyCheck: check, Token: "test-token"})
		key, err := c.Unlock("master-password-123")
		if err != nil {
			t.Fatal(err)
		}
		id, err := c.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "unsent"})
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Save(path); err != nil {
			t.Fatal(err)
		}
		err = Run(context.Background(), []string{"logout", "--cache", path, "--dev-http"}, io.Discard, io.Discard)
		server.Close()
		if (err != nil) != (status == 500) {
			t.Fatalf("unexpected logout result for %d: %v", status, err)
		}
		loaded, err := client.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		wantToken := ""
		if status == 500 {
			wantToken = "test-token"
		}
		if loaded.Session.Token != wantToken || !reflect.DeepEqual(c.Records, loaded.Records) || !reflect.DeepEqual(c.Pending[id], loaded.Pending[id]) {
			t.Fatal("logout lost data or mishandled token")
		}
	}
}
