package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/store"
	"github.com/Dja-tiger/gophkeeper/internal/testutil"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

type ownerStore struct{ db *testutil.DB }

func (s ownerStore) Apply(ctx context.Context, m model.Mutation) (model.Record, error) {
	return s.db.Apply(ctx, "alice", m)
}
func (s ownerStore) List(ctx context.Context) ([]model.Record, error) { return s.db.List(ctx, "alice") }

func TestSyncFreesQuotaBeforeAdding(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewDB()
	if err := db.CreateUser(ctx, store.User{Login: "alice"}); err != nil {
		t.Fatal(err)
	}
	r := ownerStore{db}
	c := NewCache("https://example.com", model.Session{Login: "alice"})
	// Six records occupy the entire quota; the ID to delete sorts after a new ID.
	for i := 0; i < 6; i++ {
		size := model.MaxData
		if i == 5 {
			size = model.MaxVaultData - 5*model.MaxData
		}
		id := strings.Repeat(string(rune('a'+i)), 32)
		record, err := r.Apply(ctx, model.Mutation{Operation: vault.ID(), Record: model.Record{ID: id, Data: make([]byte, size)}})
		if err != nil {
			t.Fatal(err)
		}
		c.Records[id] = record
	}
	id := strings.Repeat("0", 32)
	c.Pending[id] = model.Mutation{Operation: vault.ID(), Record: model.Record{ID: id, Data: make([]byte, 40)}}
	c.Records[id] = c.Pending[id].Record
	if err := c.Delete(strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, r); err != nil {
		t.Fatalf("queued deletion did not free quota: %v", err)
	}
	if len(c.Pending) != 0 || c.Records[id].Revision != 1 || !c.Records[strings.Repeat("f", 32)].Deleted {
		t.Fatal("queue incomplete")
	}
}

func TestLoadRejectsInconsistentCache(t *testing.T) {
	salt, check, err := VaultParameters("alice", "master-password-123")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"record-id", "revision", "missing-record", "pending-id", "pending-data", "operation", "key-check", "deleted-data"} {
		t.Run(kind, func(t *testing.T) {
			c := NewCache("https://example.com", model.Session{Login: "alice", Salt: salt, KeyCheck: check})
			id, err := c.Put(vault.Random(32), "", model.Secret{Type: "text", Title: "note", Text: "private"})
			if err != nil {
				t.Fatal(err)
			}
			m, record := c.Pending[id], c.Records[id]
			switch kind {
			case "record-id":
				record.ID = vault.ID()
			case "revision":
				record.Revision = -1
			case "missing-record":
				delete(c.Records, id)
			case "pending-id":
				m.Record.ID = vault.ID()
			case "pending-data":
				m.Record.Data = make([]byte, 40)
			case "operation":
				m.Operation = "bad"
			case "key-check":
				c.Session.KeyCheck = nil
			case "deleted-data":
				record.Deleted = true
			}
			if kind != "missing-record" {
				c.Records[id] = record
			}
			c.Pending[id] = m
			path := filepath.Join(t.TempDir(), "cache.json")
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = Load(path); err == nil {
				t.Fatal("inconsistent cache accepted")
			}
		})
	}
}

func TestLogoutAlreadyInvalidSession(t *testing.T) {
	for _, status := range []int{200, 401, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		r, err := NewRemote(server.URL, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = r.Logout(context.Background())
		server.Close()
		if status == 500 {
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Status != 500 {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatalf("logout status %d: %v", status, err)
		}
	}
}

func TestCacheRoundTripDuringConflictRecovery(t *testing.T) {
	r, c, key := setup(t)
	defer clear(key)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache.json")
	roundTrip := func() {
		t.Helper()
		if err := c.Save(path); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		c = loaded
	}
	id, err := c.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "first"})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip()
	if err = c.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	roundTrip()
	other := NewCache(c.Server, c.Session)
	if err = other.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "remote"}); err != nil {
		t.Fatal(err)
	}
	if err = other.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Put(key, id, model.Secret{Type: "text", Title: "note", Text: "local"}); err != nil {
		t.Fatal(err)
	}
	roundTrip()
	if err = c.Sync(ctx, r); err == nil {
		t.Fatal("expected conflict")
	}
	if err = c.Resolve(ctx, r, key, id, "local"); err != nil {
		t.Fatal(err)
	}
	roundTrip()
	if err = c.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	roundTrip()
	s, err := c.Read(key, id)
	if err != nil || s.Text != "local" {
		t.Fatal("local version lost", err)
	}
	if err = c.Delete(id); err != nil {
		t.Fatal(err)
	}
	roundTrip()
	if err = c.Sync(ctx, r); err != nil {
		t.Fatal(err)
	}
	roundTrip()
	if !c.Records[id].Deleted {
		t.Fatal("tombstone lost")
	}
}
