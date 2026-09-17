package client

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/api"
	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/testutil"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func setup(t *testing.T) (*Remote, *Cache, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(api.New(testutil.NewDB()))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	r, e := NewRemote(server.URL, false, ca)
	if e != nil {
		t.Fatal(e)
	}
	salt, check, e := VaultParameters("alice", "master-password-123")
	if e != nil {
		t.Fatal(e)
	}
	s, e := r.Register(context.Background(), model.Credentials{Login: "alice", Password: "authentication-123", Salt: salt, KeyCheck: check})
	if e != nil {
		t.Fatal(e)
	}
	r.Token = s.Token
	c := NewCache(r.URL, s)
	key, e := c.Unlock("master-password-123")
	if e != nil {
		t.Fatal(e)
	}
	return r, c, key
}
func TestTwoClientsConflictAndDeletion(t *testing.T) {
	r, a, key := setup(t)
	ctx := context.Background()
	b := NewCache(a.Server, a.Session)
	id, e := a.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "first", Metadata: "private metadata"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "second"}); e == nil {
		t.Fatal("pending edit overwritten")
	}
	if e = a.Sync(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e = b.Sync(ctx, r); e != nil {
		t.Fatal(e)
	}
	first, e := b.Read(key, id)
	if e != nil || first.Text != "first" {
		t.Fatal(first, e)
	}
	a.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "alice edit"})
	b.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "bob edit"})
	if e = a.Sync(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e = b.Sync(ctx, r); e == nil || len(b.Pending) != 1 {
		t.Fatal("conflict lost")
	}
	if e = b.Resolve(ctx, r, key, id, "local"); e != nil {
		t.Fatal(e)
	}
	if e = b.Sync(ctx, r); e != nil {
		t.Fatal(e)
	}
	a.Sync(ctx, r)
	s, _ := a.Read(key, id)
	if s.Text != "bob edit" {
		t.Fatal(s.Text)
	}
	a.Delete(id)
	b.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "keep after deletion"})
	a.Sync(ctx, r)
	if e = b.Sync(ctx, r); e == nil {
		t.Fatal("deleted record resurrected")
	}
	if e = b.Resolve(ctx, r, key, id, "local"); e != nil {
		t.Fatal(e)
	}
	if e = b.Sync(ctx, r); e != nil {
		t.Fatal(e)
	}
	a.Sync(ctx, r)
	if _, e = a.Read(key, id); !errors.Is(e, model.ErrNotFound) {
		t.Fatal("old ID resurrected")
	}
	if len(a.Records) != 2 {
		t.Fatal("new ID missing")
	}
	for newID, v := range a.Records {
		if !v.Deleted {
			a.Put(key, newID, model.Secret{Type: "text", Title: "local", Text: "discard me"})
			if e = a.Resolve(ctx, r, key, newID, "remote"); e != nil {
				t.Fatal(e)
			}
			s, _ = a.Read(key, newID)
			if s.Text != "keep after deletion" {
				t.Fatal("remote resolution failed")
			}
		}
	}
}

type flaky struct {
	Transport
	fail bool
}

func (f *flaky) Apply(ctx context.Context, m model.Mutation) (model.Record, error) {
	r, e := f.Transport.Apply(ctx, m)
	if f.fail {
		f.fail = false
		return model.Record{}, errors.New("response lost")
	}
	return r, e
}
func TestRetryAndCache(t *testing.T) {
	r, c, key := setup(t)
	id, e := c.Put(key, "", model.Secret{Type: "credentials", Title: "account", Login: "private-user", Password: "private-secret"})
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if e = c.Save(path); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("private-secret")) || bytes.Contains(data, []byte("private-user")) {
		t.Fatal("plaintext leaked")
	}
	loaded, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	f := &flaky{Transport: r, fail: true}
	if e = loaded.Sync(context.Background(), f); e == nil {
		t.Fatal("expected lost response")
	}
	if e = loaded.Sync(context.Background(), f); e != nil {
		t.Fatal(e)
	}
	if loaded.Records[id].Revision != 1 {
		t.Fatal("duplicate mutation")
	}
	release, e := Lock(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Lock(path); e == nil {
		t.Fatal("concurrent lock accepted")
	}
	release()
	release, e = Lock(path)
	if e != nil {
		t.Fatal(e)
	}
	release()
	if _, e = loaded.Unlock("wrong-vault-password"); e == nil {
		t.Fatal("wrong password accepted")
	}
	if _, e = Load(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("missing cache")
	}
	os.WriteFile(path, []byte(`{}`), 0600)
	if _, e = Load(path); e == nil {
		t.Fatal("invalid cache accepted")
	}
	os.WriteFile(path, []byte(`broken`), 0600)
	if _, e = Load(path); e == nil {
		t.Fatal("broken cache accepted")
	}
	if e = c.Save(filepath.Join(path, "child")); e == nil {
		t.Fatal("file used as directory")
	}
}
func TestRemoteSecurityAndFailures(t *testing.T) {
	for _, address := range []string{"http://example.com", "https://u:p@example.com", "https://example.com/path", "https://example.com?q=a", "ftp://localhost", "::bad"} {
		if _, e := NewRemote(address, true, nil); e == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	if _, e := NewRemote("https://localhost", false, []byte("bad CA")); e == nil {
		t.Fatal("bad CA accepted")
	}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/login":
			w.WriteHeader(401)
		case "/v1/records":
			w.WriteHeader(429)
		default:
			http.Redirect(w, r, "https://example.com", 302)
		}
	}))
	defer h.Close()
	r, e := NewRemote(h.URL, true, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Login(context.Background(), model.Credentials{}); e == nil || !strings.Contains(e.Error(), "credentials") {
		t.Fatal(e)
	}
	if _, e = r.List(context.Background()); e == nil || !strings.Contains(e.Error(), "attempts") {
		t.Fatal(e)
	}
	if e = r.Logout(context.Background()); e == nil {
		t.Fatal("redirect accepted")
	}
	if e = r.call(context.Background(), "POST", "/", make(chan int), nil); e == nil {
		t.Fatal("invalid json accepted")
	}
	for _, status := range []int{409, 500} {
		if (&Error{Status: status}).Error() == "" {
			t.Fatal("missing error")
		}
	}
}
func TestCacheInvalidOperations(t *testing.T) {
	c := NewCache("https://example.com", model.Session{Login: "alice"})
	key := vault.Random(32)
	if _, e := c.Put(key, "", model.Secret{}); e == nil {
		t.Fatal("invalid secret accepted")
	}
	if _, e := c.Put(key, "bad", model.Secret{Type: "text", Title: "x", Text: "x"}); e == nil {
		t.Fatal("invalid id accepted")
	}
	if _, e := c.Put(key, vault.ID(), model.Secret{Type: "text", Title: "x", Text: "x"}); e == nil {
		t.Fatal("missing edit accepted")
	}
	if e := c.Delete("missing"); e == nil {
		t.Fatal("missing delete")
	}
	id, _ := c.Put(key, "", model.Secret{Type: "binary", Title: "empty", Filename: "empty.bin"})
	if e := c.Delete(id); e == nil {
		t.Fatal("pending deletion accepted")
	}
	if e := c.Resolve(context.Background(), nil, key, "missing", "local"); e == nil {
		t.Fatal("missing resolution")
	}
	if e := c.Resolve(context.Background(), nil, key, id, "invalid"); e == nil {
		t.Fatal("invalid resolution")
	}
}

type snapshot struct{ records []model.Record }

func (s snapshot) List(context.Context) ([]model.Record, error) { return s.records, nil }
func (s snapshot) Apply(context.Context, model.Mutation) (model.Record, error) {
	return model.Record{}, errors.New("unexpected write")
}
func TestInvalidSnapshotDoesNotReplaceCache(t *testing.T) {
	id := vault.ID()
	original := model.Record{ID: id, Revision: 1, Data: make([]byte, 40)}
	for _, records := range [][]model.Record{{{ID: "invalid", Revision: 1}}, {original, original}, make([]model.Record, model.MaxRecords+1)} {
		c := NewCache("https://example.com", model.Session{Login: "alice"})
		c.Records[id] = original
		if e := c.Sync(context.Background(), snapshot{records}); e == nil {
			t.Fatal("invalid snapshot accepted")
		}
		if len(c.Records) != 1 || c.Records[id].ID != id {
			t.Fatal("cache replaced after invalid snapshot")
		}
	}
}
