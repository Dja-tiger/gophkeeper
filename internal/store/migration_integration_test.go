//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

//go:embed testdata/schema_v1.sql
var legacySchema string

func migrationFixture(t *testing.T) (*Postgres, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("GOPHKEEPER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("disposable database required")
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "migration_" + vault.ID()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{namespace}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{namespace}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = namespace
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Postgres{pool: pool}, pool
}

func TestMigrationPreservesLegacyDataAndLimits(t *testing.T) {
	ctx := context.Background()
	db, pool := migrationFixture(t)
	if _, err := pool.Exec(ctx, legacySchema); err != nil {
		t.Fatal(err)
	}
	salt, check := make([]byte, 16), make([]byte, 40)
	for _, login := range []string{"alice", "bob"} {
		if _, err := pool.Exec(ctx, "INSERT INTO users VALUES($1,$2,$3,$4)", login, []byte("hash"), salt, check); err != nil {
			t.Fatal(err)
		}
	}
	token := strings.Repeat("a", 64)
	if _, err := pool.Exec(ctx, "INSERT INTO sessions VALUES($1,$2,$3)", token, "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	m := model.Mutation{Operation: vault.ID(), Record: model.Record{ID: vault.ID(), Data: bytes.Repeat([]byte{3}, 40)}}
	record := m.Record
	record.Revision = 1
	if _, err := pool.Exec(ctx, "INSERT INTO records VALUES($1,$2,$3,$4,$5)", "alice", record.ID, record.Revision, false, record.Data); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(m)
	hash := sha256.Sum256(request)
	receipt := record
	receipt.Data = nil
	result, _ := json.Marshal(receipt)
	if _, err := pool.Exec(ctx, "INSERT INTO operations VALUES($1,$2,$3,$4)", "alice", m.Operation, hash[:], result); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	u, err := db.User(ctx, "alice")
	if err != nil || !bytes.Equal(u.Salt, salt) || !bytes.Equal(u.KeyCheck, check) || string(u.Hash) != "hash" {
		t.Fatal("vault parameters lost", err)
	}
	if login, err := db.Session(ctx, token, time.Now()); err != nil || login != "alice" {
		t.Fatal("session lost", err)
	}
	records, err := db.List(ctx, "alice")
	if err != nil || len(records) != 1 || !bytes.Equal(records[0].Data, record.Data) {
		t.Fatal("record lost", err)
	}
	replay, err := db.Apply(ctx, "alice", m)
	if err != nil || replay.Revision != 1 || !bytes.Equal(replay.Data, m.Record.Data) {
		t.Fatal("operation receipt lost", err)
	}
	m.Operation = vault.ID()
	m.Base = 1
	m.Record.Labels = []string{"work"}
	if _, err = db.Apply(ctx, "alice", m); err != nil {
		t.Fatal(err)
	}
	if records, err = db.ListByLabel(ctx, "alice", "work"); err != nil || len(records) != 1 {
		t.Fatal("label lookup failed", err)
	}
	if records, err = db.ListByLabel(ctx, "bob", "work"); err != nil || len(records) != 0 {
		t.Fatal("cross-owner label lookup", err)
	}
	if err = db.CreateUser(ctx, User{Login: "charlie", Hash: []byte("hash"), Salt: salt, KeyCheck: check}); err != nil {
		t.Fatal("identity sequence failed", err)
	}
	var userID int64
	if err = pool.QueryRow(ctx, "SELECT id FROM users WHERE login='alice'").Scan(&userID); err != nil || userID < 1 {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET login='renamed' WHERE id=$1", userID); err != nil {
		t.Fatal(err)
	}
	if login, err := db.Session(ctx, token, time.Now()); err != nil || login != "renamed" {
		t.Fatal("session still depends on login", err)
	}
	if records, err = db.List(ctx, "renamed"); err != nil || len(records) != 1 {
		t.Fatal("owner references changed", err)
	}
	for _, tc := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO users(login,password_hash,salt,key_check) VALUES($1,$2,$3,$4)", []any{strings.Repeat("x", 65), []byte("hash"), salt, check}},
		{"INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", []any{strings.Repeat("x", 65), userID, time.Now()}},
		{"INSERT INTO records(user_id,id,revision,deleted,data) VALUES($1,$2,1,false,$3)", []any{userID, strings.Repeat("x", 33), make([]byte, 40)}},
		{"INSERT INTO operations(user_id,id,request_hash,result) VALUES($1,$2,$3,'{}')", []any{userID, strings.Repeat("x", 33), make([]byte, 32)}},
	} {
		if _, err = pool.Exec(ctx, tc.query, tc.args...); err == nil {
			t.Fatal("accepted oversized value", tc.query)
		}
	}
	if err = db.CreateSession(ctx, strings.Repeat("b", 64), "renamed", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteExpiredSessions(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&remaining); err != nil || remaining != 1 {
		t.Fatal("cleanup removed live session or kept expired", err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	db, pool := migrationFixture(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, legacySchema); err != nil {
		t.Fatal(err)
	}
	login := strings.Repeat("x", 65)
	if _, err := pool.Exec(ctx, "INSERT INTO users VALUES($1,$2,$3,$4)", login, []byte("hash"), make([]byte, 16), make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err == nil {
		t.Fatal("invalid legacy data silently truncated")
	}
	var got string
	if err := pool.QueryRow(ctx, "SELECT login FROM users").Scan(&got); err != nil || got != login {
		t.Fatal("legacy data damaged", err)
	}
	var ids int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='users' AND column_name='id'").Scan(&ids); err != nil || ids != 0 {
		t.Fatal("migration partly committed", err)
	}
}
