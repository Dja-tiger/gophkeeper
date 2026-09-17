//go:build integration

package store_test

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/api"
	"github.com/Dja-tiger/gophkeeper/internal/client"
	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/store"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func TestPostgresLifecycleAndConcurrentWrites(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("GOPHKEEPER_TEST_DATABASE_URL must reference a disposable PostgreSQL database")
	}
	ctx := context.Background()
	db, e := store.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(ctx); e != nil {
		t.Fatal("migration not idempotent", e)
	}
	owner := "test-" + vault.ID()
	other := "other-" + vault.ID()
	salt, check, e := client.VaultParameters(owner, "master-password-123")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(api.New(db))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	r, e := client.NewRemote(server.URL, false, ca)
	if e != nil {
		t.Fatal(e)
	}
	credentials := model.Credentials{Login: owner, Password: "authentication-123", Salt: salt, KeyCheck: check}
	session, e := r.Register(ctx, credentials)
	if e != nil {
		t.Fatal(e)
	}
	r.Token = session.Token
	c := client.NewCache(r.URL, session)
	key, e := c.Unlock("master-password-123")
	if e != nil {
		t.Fatal(e)
	}
	id, e := c.Put(key, "", model.Secret{Type: "text", Title: "integration", Text: "must remain encrypted"})
	if e != nil {
		t.Fatal(e)
	}
	op := c.Pending[id]
	if e = c.Sync(ctx, r); e != nil {
		t.Fatal(e)
	}
	replay, e := r.Apply(ctx, op)
	if e != nil || replay.Revision != 1 {
		t.Fatal("replay", e)
	}
	if _, e = r.Login(ctx, model.Credentials{Login: owner, Password: "authentication-123"}); e != nil {
		t.Fatal(e)
	}
	if e = db.CreateUser(ctx, store.User{Login: other, Hash: []byte("test hash"), Salt: make([]byte, 16), KeyCheck: make([]byte, 40)}); e != nil {
		t.Fatal(e)
	}
	if got, e := db.List(ctx, other); e != nil || len(got) != 0 {
		t.Fatal("owner isolation", got, e)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := model.Mutation{Operation: vault.ID(), Base: 1, Record: model.Record{ID: id, Data: make([]byte, 40)}}
			if _, e := db.Apply(ctx, owner, m); e == nil {
				winners.Add(1)
			} else if !errors.Is(e, model.ErrConflict) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent winners = %d", winners.Load())
	}
	foreign := model.Mutation{Operation: vault.ID(), Base: 2, Record: model.Record{ID: id, Deleted: true}}
	if _, e = db.Apply(ctx, other, foreign); !errors.Is(e, model.ErrConflict) {
		t.Fatal("foreign delete", e)
	}
	deleted, e := db.Apply(ctx, owner, foreign)
	if e != nil || !deleted.Deleted {
		t.Fatal(e)
	}
	foreign.Operation = vault.ID()
	foreign.Base = 3
	foreign.Record.Deleted = false
	foreign.Record.Data = make([]byte, 40)
	if _, e = db.Apply(ctx, owner, foreign); !errors.Is(e, model.ErrConflict) {
		t.Fatal("resurrection", e)
	}
	if e = r.Logout(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = r.List(ctx); e == nil {
		t.Fatal("revoked token accepted")
	}
	db.CreateSession(ctx, "expired-"+owner, owner, time.Now().Add(-time.Hour))
	if _, e = db.Session(ctx, "expired-"+owner, time.Now()); !errors.Is(e, model.ErrNotFound) {
		t.Fatal("expired session", e)
	}
	// A new pool proves persistence independently of in-process objects.
	again, e := store.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	records, e := again.List(ctx, owner)
	if e != nil || len(records) != 1 || !records[0].Deleted {
		t.Fatal("persistence", records, e)
	}
}
