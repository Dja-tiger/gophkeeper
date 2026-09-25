package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/model"
)

type customTransport struct{}

func (customTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected request")
}

func TestRemoteDoesNotDependOnDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = customTransport{}
	defer func() { http.DefaultTransport = original }()
	remote, err := NewRemote("https://example.com", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := remote.HTTP.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSHandshakeTimeout == 0 {
		t.Fatal("invalid transport")
	}
	transport.CloseIdleConnections()
}

func TestCacheValidationReportsInvariant(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*Cache)
	}{
		{"version", "unsupported cache version", func(c *Cache) { c.Version = 2 }},
		{"server", "cache server is missing", func(c *Cache) { c.Server = "" }},
		{"login", "invalid cache login", func(c *Cache) { c.Session.Login = "!" }},
		{"salt", "cache salt must be 16 bytes", func(c *Cache) { c.Session.Salt = nil }},
		{"key-check", "cache key check must be 29–256 bytes", func(c *Cache) { c.Session.KeyCheck = nil }},
		{"records", "cache records are missing", func(c *Cache) { c.Records = nil }},
		{"pending", "cache pending operations are missing", func(c *Cache) { c.Pending = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache("https://example.com", model.Session{Login: "alice", Salt: make([]byte, 16), KeyCheck: make([]byte, 40)})
			tc.change(c)
			if err := c.validate(); err == nil || err.Error() != tc.want {
				t.Fatalf("got %v; want %s", err, tc.want)
			}
		})
	}
}

func TestPublicLabelSearchPreservesEncryptedMetadata(t *testing.T) {
	r, c, key := setup(t)
	defer clear(key)
	ctx := context.Background()
	secret := model.Secret{Type: "text", Title: "secret title", Text: "private text", Metadata: "private activation code"}
	id, err := c.PutWithLabels(key, "", secret, []string{"work"})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	records, err := r.ListByLabel(ctx, "work")
	if err != nil || len(records) != 1 || records[0].ID != id {
		t.Fatal("search failed", err)
	}
	wire, _ := json.Marshal(records)
	if bytes.Contains(wire, []byte(secret.Metadata)) || bytes.Contains(wire, []byte(secret.Title)) {
		t.Fatal("metadata exposed")
	}
	if _, err = c.Put(key, id, secret); err != nil {
		t.Fatal(err)
	}
	if len(c.Pending[id].Record.Labels) != 1 {
		t.Fatal("ordinary edit dropped public labels")
	}
	if err = c.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = c.PutWithLabels(key, id, secret, nil); err != nil {
		t.Fatal(err)
	}
	if err = c.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	if records, err = r.ListByLabel(ctx, "work"); err != nil || len(records) != 0 {
		t.Fatal("labels were not cleared", err)
	}
	if _, err = r.ListByLabel(ctx, ""); err == nil {
		t.Fatal("empty label accepted")
	}
}
