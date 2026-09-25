package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/api"
	"github.com/Dja-tiger/gophkeeper/internal/client"
	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/testutil"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func TestStaleCLIWritePreservesConcurrentEdit(t *testing.T) {
	for _, command := range []string{"edit", "delete"} {
		t.Run(command, func(t *testing.T) {
			ctx := context.Background()
			server := httptest.NewServer(api.New(testutil.NewDB(), slog.Default()))
			defer server.Close()
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
			r.Token = session.Token
			a := client.NewCache(server.URL, session)
			key, err := a.Unlock("master-password-123")
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			id, err := a.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "original"})
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Sync(ctx, r); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "cache.json")
			if err = a.Save(path); err != nil {
				t.Fatal(err)
			}
			if _, err = a.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "concurrent edit"}); err != nil {
				t.Fatal(err)
			}
			if err = a.Sync(ctx, r); err != nil {
				t.Fatal(err)
			}
			master, input := filepath.Join(dir, "master"), filepath.Join(dir, "input")
			if err = os.WriteFile(master, []byte("master-password-123"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(input, []byte(`{"type":"text","title":"note","text":"stale edit"}`), 0600); err != nil {
				t.Fatal(err)
			}
			err = Run(ctx, []string{command, "--cache", path, "--dev-http", "--id", id, "--input", input, "--vault-password-file", master}, io.Discard, io.Discard)
			var apiErr *client.Error
			if !errors.As(err, &apiErr) || apiErr.Status != 409 {
				t.Fatalf("expected conflict, got %v", err)
			}
			cached, err := client.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(cached.Pending) != 1 || cached.Pending[id].Base != 1 {
				t.Fatal("stale write was not preserved for resolution")
			}
			if err = a.Sync(ctx, r); err != nil {
				t.Fatal(err)
			}
			s, err := a.Read(key, id)
			if err != nil || s.Text != "concurrent edit" {
				t.Fatal("concurrent edit lost", err)
			}
		})
	}
}

func TestLoginRejectsChangedVault(t *testing.T) {
	ctx := context.Background()
	salt, check, err := client.VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	oldSession := model.Session{Login: "alice", Salt: salt, KeyCheck: check, Token: "old-token"}
	newSalt, newCheck, err := client.VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"salt", "key-check", "login"} {
		t.Run(kind, func(t *testing.T) {
			session := oldSession
			session.Token = "new-token"
			switch kind {
			case "salt":
				session.Salt, session.KeyCheck = newSalt, newCheck
			case "key-check":
				key, e := client.NewCache("", oldSession).Unlock("master-password-123")
				if e != nil {
					t.Fatal(e)
				}
				// A second valid check under the same key is still a changed immutable parameter.
				session.KeyCheck, e = vault.Seal(key, []byte("gophkeeper-vault-v1"), "gophkeeper/v1/check/alice")
				clear(key)
				if e != nil {
					t.Fatal(e)
				}
			case "login":
				session.Login = "other"
			}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/login":
					json.NewEncoder(w).Encode(session)
				case "/v1/logout":
					w.WriteHeader(http.StatusNoContent)
				default:
					requests++
					io.WriteString(w, "[]")
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			path := filepath.Join(dir, "cache.json")
			c := client.NewCache(server.URL, oldSession)
			key, e := c.Unlock("master-password-123")
			if e != nil {
				t.Fatal(e)
			}
			_, e = c.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "unsent"})
			clear(key)
			if e != nil {
				t.Fatal(e)
			}
			if e = c.Save(path); e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			auth, master := filepath.Join(dir, "auth"), filepath.Join(dir, "master")
			if e = os.WriteFile(auth, []byte("authentication-123"), 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(master, []byte("master-password-123"), 0600); e != nil {
				t.Fatal(e)
			}
			e = Run(ctx, []string{"login", "--cache", path, "--server", server.URL, "--login", "alice", "--dev-http", "--auth-password-file", auth, "--vault-password-file", master}, io.Discard, io.Discard)
			if e == nil {
				t.Fatal("changed vault accepted")
			}
			after, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(before, after) || requests != 0 {
				t.Fatal("cache changed or queued data sent to a different vault")
			}
		})
	}
}

func TestOfflineDoesNotRequireTransport(t *testing.T) {
	salt, check, err := client.VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, master := filepath.Join(dir, "cache.json"), filepath.Join(dir, "master")
	c := client.NewCache("http://localhost:1", model.Session{Login: "alice", Salt: salt, KeyCheck: check})
	if err = c.Save(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(master, []byte("master-password-123"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Run(context.Background(), []string{"list", "--offline", "--cache", path, "--ca", filepath.Join(dir, "missing-ca"), "--vault-password-file", master}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"login", "register", "sync", "logout", "resolve"} {
		if err = Run(context.Background(), []string{command, "--offline", "--cache", path}, io.Discard, io.Discard); err == nil {
			t.Fatalf("%s accepted incompatible offline flag", command)
		}
	}
}
