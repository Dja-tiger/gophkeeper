package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func fixture(t *testing.T) (*Postgres, pgxmock.PgxPoolIface) {
	t.Helper()
	m, e := pgxmock.NewPool()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := m.ExpectationsWereMet(); e != nil {
			t.Error(e)
		}
		m.Close()
	})
	return &Postgres{pool: m}, m
}
func TestUserAndSessionSQL(t *testing.T) {
	p, m := fixture(t)
	ctx := context.Background()
	u := User{Login: "alice", Hash: []byte("hash"), Salt: make([]byte, 16), KeyCheck: []byte("check")}
	m.ExpectExec("INSERT INTO users").WithArgs(u.Login, u.Hash, u.Salt, u.KeyCheck).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	if e := p.CreateUser(ctx, u); e != nil {
		t.Fatal(e)
	}
	m.ExpectExec("INSERT INTO users").WithArgs(u.Login, u.Hash, u.Salt, u.KeyCheck).WillReturnError(&pgconn.PgError{Code: "23505"})
	if !errors.Is(p.CreateUser(ctx, u), model.ErrExists) {
		t.Fatal("duplicate mapping")
	}
	m.ExpectQuery("SELECT password_hash").WithArgs("alice").WillReturnRows(pgxmock.NewRows([]string{"password_hash", "salt", "key_check"}).AddRow(u.Hash, u.Salt, u.KeyCheck))
	got, e := p.User(ctx, "alice")
	if e != nil || got.Login != "alice" {
		t.Fatal(got, e)
	}
	m.ExpectQuery("SELECT password_hash").WithArgs("missing").WillReturnError(pgx.ErrNoRows)
	if _, e = p.User(ctx, "missing"); !errors.Is(e, model.ErrNotFound) {
		t.Fatal(e)
	}
	now := time.Now()
	m.ExpectExec("INSERT INTO sessions").WithArgs("hash", "alice", now).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	if e = p.CreateSession(ctx, "hash", "alice", now); e != nil {
		t.Fatal(e)
	}
	m.ExpectQuery("SELECT u.login FROM sessions").WithArgs("hash", now).WillReturnRows(pgxmock.NewRows([]string{"login"}).AddRow("alice"))
	if login, e := p.Session(ctx, "hash", now); e != nil || login != "alice" {
		t.Fatal(login, e)
	}
	m.ExpectQuery("SELECT u.login FROM sessions").WithArgs("hash", now).WillReturnError(pgx.ErrNoRows)
	if _, e = p.Session(ctx, "hash", now); !errors.Is(e, model.ErrNotFound) {
		t.Fatal(e)
	}
	m.ExpectExec("DELETE FROM sessions").WithArgs("hash").WillReturnResult(pgxmock.NewResult("DELETE", 1))
	if e = p.DeleteSession(ctx, "hash"); e != nil {
		t.Fatal(e)
	}
	m.ExpectExec("DELETE FROM sessions").WithArgs(now).WillReturnError(errors.New("cleanup failed"))
	if e = p.DeleteExpiredSessions(ctx, now); e == nil {
		t.Fatal("cleanup error ignored")
	}
	m.ExpectExec("INSERT INTO sessions").WithArgs("hash", "alice", now).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	if e = p.CreateSession(ctx, "hash", "alice", now); e != nil {
		t.Fatal("cleanup failure blocked login", e)
	}
}
func TestListSQL(t *testing.T) {
	p, m := fixture(t)
	ctx := context.Background()
	m.ExpectQuery("SELECT id,revision,deleted,data,labels FROM records WHERE user_id=.* ORDER BY id").WithArgs("alice").WillReturnRows(pgxmock.NewRows([]string{"id", "revision", "deleted", "data", "labels"}).AddRow("id", int64(1), false, []byte("encrypted"), []string{"work"}))
	r, e := p.List(ctx, "alice")
	if e != nil || len(r) != 1 {
		t.Fatal(r, e)
	}
	m.ExpectQuery("SELECT id").WithArgs("alice").WillReturnError(errors.New("db"))
	if _, e = p.List(ctx, "alice"); e == nil {
		t.Fatal("query error ignored")
	}
	m.ExpectQuery("SELECT id").WithArgs("alice").WillReturnRows(pgxmock.NewRows([]string{"id", "revision", "deleted", "data", "labels"}).AddRow("id", "bad", false, nil, []string{}))
	if _, e = p.List(ctx, "alice"); e == nil {
		t.Fatal("scan error ignored")
	}
}
func TestMigrate(t *testing.T) {
	for _, mode := range []string{"fresh", "legacy", "current", "newer", "failed-upgrade"} {
		t.Run(mode, func(t *testing.T) {
			p, m := fixture(t)
			m.ExpectBegin()
			m.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(pgxmock.NewResult("SELECT", 1))
			m.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").WillReturnResult(pgxmock.NewResult("CREATE", 0))
			version := 0
			if mode == "current" {
				version = 2
			}
			if mode == "newer" {
				version = 3
			}
			m.ExpectQuery("SELECT COALESCE").WillReturnRows(pgxmock.NewRows([]string{"version"}).AddRow(version))
			if version == 0 {
				m.ExpectQuery("SELECT EXISTS").WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(mode != "fresh"))
				if mode == "fresh" {
					m.ExpectExec("CREATE TABLE IF NOT EXISTS users").WillReturnResult(pgxmock.NewResult("CREATE", 0))
				} else {
					q := m.ExpectExec("ALTER TABLE users ADD COLUMN id")
					if mode == "failed-upgrade" {
						q.WillReturnError(errors.New("upgrade failed"))
					} else {
						q.WillReturnResult(pgxmock.NewResult("ALTER", 0))
					}
				}
			}
			failed := mode == "newer" || mode == "failed-upgrade"
			if !failed {
				m.ExpectExec("INSERT INTO schema_migrations").WillReturnResult(pgxmock.NewResult("INSERT", 1))
				m.ExpectCommit()
			}
			m.ExpectRollback()
			if err := p.Migrate(context.Background()); (err != nil) != failed {
				t.Fatal(mode, err)
			}
		})
	}
}
func TestApplyTransactions(t *testing.T) {
	for _, mode := range []string{"create", "conflict", "deleted", "replay", "reused", "limit", "write-error", "commit-error"} {
		t.Run(mode, func(t *testing.T) {
			p, mock := fixture(t)
			ctx := context.Background()
			m := model.Mutation{Operation: vault.ID(), Record: model.Record{ID: vault.ID(), Data: make([]byte, 40)}}
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT id FROM users").WithArgs("alice").WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(int64(7)))
			if mode == "replay" || mode == "reused" {
				b, _ := json.Marshal(m)
				hash := sha256.Sum256(b)
				if mode == "reused" {
					hash[0] ^= 1
				}
				r := m.Record
				r.Revision = 1
				r.Data = nil // Real receipts do not duplicate ciphertext.
				result, _ := json.Marshal(r)
				mock.ExpectQuery("SELECT request_hash,result").WithArgs(int64(7), m.Operation).WillReturnRows(pgxmock.NewRows([]string{"request_hash", "result"}).AddRow(hash[:], result))
			} else {
				mock.ExpectQuery("SELECT request_hash,result").WithArgs(int64(7), m.Operation).WillReturnError(pgx.ErrNoRows)
				if mode == "conflict" || mode == "deleted" {
					mock.ExpectQuery("SELECT revision,deleted").WithArgs(int64(7), m.Record.ID).WillReturnRows(pgxmock.NewRows([]string{"revision", "deleted"}).AddRow(int64(1), mode == "deleted"))
				} else {
					mock.ExpectQuery("SELECT revision,deleted").WithArgs(int64(7), m.Record.ID).WillReturnError(pgx.ErrNoRows)
					n := 0
					if mode == "limit" {
						n = model.MaxRecords
					}
					mock.ExpectQuery("SELECT count").WithArgs(int64(7)).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(n))
					if mode != "limit" {
						mock.ExpectQuery("SELECT COALESCE").WithArgs(int64(7), m.Record.ID).WillReturnRows(pgxmock.NewRows([]string{"sum"}).AddRow(int64(0)))
						q := mock.ExpectExec("INSERT INTO records").WithArgs(int64(7), m.Record.ID, int64(1), false, m.Record.Data, []string{})
						if mode == "write-error" {
							q.WillReturnError(errors.New("db"))
						} else {
							q.WillReturnResult(pgxmock.NewResult("INSERT", 1))
							mock.ExpectExec("INSERT INTO operations").WithArgs(int64(7), m.Operation, pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
							commit := mock.ExpectCommit()
							if mode == "commit-error" {
								commit.WillReturnError(errors.New("commit failed"))
							}
						}
					}
				}
			}
			mock.ExpectRollback()
			r, e := p.Apply(ctx, "alice", m)
			if mode == "create" || mode == "replay" {
				if e != nil || r.Revision != 1 || len(r.Data) != len(m.Record.Data) {
					t.Fatal(r, e)
				}
			} else if e == nil {
				t.Fatal("expected failure", mode)
			}
		})
	}
	p, _ := fixture(t)
	if _, e := p.Apply(context.Background(), "alice", model.Mutation{}); e == nil {
		t.Fatal("invalid mutation accepted")
	}
}

func TestAccountDataQuota(t *testing.T) {
	p, mock := fixture(t)
	m := model.Mutation{Operation: vault.ID(), Record: model.Record{ID: vault.ID(), Data: make([]byte, 40)}}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM users").WithArgs("alice").WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(int64(7)))
	mock.ExpectQuery("SELECT request_hash,result").WithArgs(int64(7), m.Operation).WillReturnError(pgx.ErrNoRows)
	mock.ExpectQuery("SELECT revision,deleted").WithArgs(int64(7), m.Record.ID).WillReturnError(pgx.ErrNoRows)
	mock.ExpectQuery("SELECT count").WithArgs(int64(7)).WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COALESCE").WithArgs(int64(7), m.Record.ID).WillReturnRows(pgxmock.NewRows([]string{"sum"}).AddRow(int64(model.MaxVaultData)))
	mock.ExpectRollback()
	if _, e := p.Apply(context.Background(), "alice", m); !errors.Is(e, model.ErrLimit) {
		t.Fatal(e)
	}
}
