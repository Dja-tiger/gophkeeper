package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Dja-tiger/gophkeeper/internal/model"
)

//go:embed schema.sql
var schema string

//go:embed migrations/002_user_identity.sql
var userIdentityMigration string

type database interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Close()
}

// Postgres implements Store using a concurrency-safe connection pool.
type Postgres struct{ pool database }

// New opens and verifies a PostgreSQL connection pool; Close releases it.
func New(ctx context.Context, dsn string) (*Postgres, error) {
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Postgres{p}, nil
}

// Close releases all database connections.
func (p *Postgres) Close() { p.pool.Close() }

// Migrate installs or upgrades the schema atomically under a database advisory lock.
// Legacy login-based tables are upgraded to version 2 without dropping account data.
func (p *Postgres) Migrate(ctx context.Context) error {
	tx, e := p.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(719053210)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY CHECK(version>0))"); e != nil {
		return e
	}
	var version int
	if e = tx.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM schema_migrations").Scan(&version); e != nil {
		return e
	}
	if version > 2 {
		return errors.New("database schema is newer than this server")
	}
	if version == 0 {
		var legacy bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='users')").Scan(&legacy); e != nil {
			return e
		}
		if legacy {
			version = 1
		} else {
			if _, e = tx.Exec(ctx, schema); e != nil {
				return e
			}
			version = 2
		}
	}
	if version == 1 {
		if _, e = tx.Exec(ctx, userIdentityMigration); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES(2) ON CONFLICT DO NOTHING"); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// CreateUser registers an account; duplicate login names return model.ErrExists.
func (p *Postgres) CreateUser(ctx context.Context, u User) error {
	_, e := p.pool.Exec(ctx, "INSERT INTO users(login,password_hash,salt,key_check) VALUES($1,$2,$3,$4)", u.Login, u.Hash, u.Salt, u.KeyCheck)
	var pe *pgconn.PgError
	if errors.As(e, &pe) && pe.Code == "23505" {
		return model.ErrExists
	}
	return e
}

// User loads authentication and vault parameters by login.
func (p *Postgres) User(ctx context.Context, login string) (User, error) {
	u := User{Login: login}
	e := p.pool.QueryRow(ctx, "SELECT password_hash,salt,key_check FROM users WHERE login=$1", login).Scan(&u.Hash, &u.Salt, &u.KeyCheck)
	if errors.Is(e, pgx.ErrNoRows) {
		e = model.ErrNotFound
	}
	return u, e
}

// CreateSession persists a token hash without coupling login to expired-session cleanup.
func (p *Postgres) CreateSession(ctx context.Context, hash, login string, expiry time.Time) error {
	_, e := p.pool.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,(SELECT id FROM users WHERE login=$2),$3)", hash, login, expiry)
	return e
}

// DeleteExpiredSessions removes expired sessions independently of authentication requests.
func (p *Postgres) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, e := p.pool.Exec(ctx, "DELETE FROM sessions WHERE expires_at <= $1", now)
	return e
}

// Session returns the owner of an unexpired token hash.
func (p *Postgres) Session(ctx context.Context, hash string, now time.Time) (string, error) {
	var login string
	e := p.pool.QueryRow(ctx, "SELECT u.login FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2", hash, now).Scan(&login)
	if errors.Is(e, pgx.ErrNoRows) {
		e = model.ErrNotFound
	}
	return login, e
}

// DeleteSession revokes a token hash and is idempotent.
func (p *Postgres) DeleteSession(ctx context.Context, hash string) error {
	_, e := p.pool.Exec(ctx, "DELETE FROM sessions WHERE token_hash=$1", hash)
	return e
}

// List returns an ordered full snapshot, including tombstones, for one owner only.
func (p *Postgres) List(ctx context.Context, login string) ([]model.Record, error) {
	return p.list(ctx, "SELECT id,revision,deleted,data,labels FROM records WHERE user_id=(SELECT id FROM users WHERE login=$1) ORDER BY id", login)
}

// ListByLabel returns only the owner's live records matching an exact public label.
func (p *Postgres) ListByLabel(ctx context.Context, login, label string) ([]model.Record, error) {
	if e := model.ValidateLabels([]string{label}); e != nil {
		return nil, e
	}
	return p.list(ctx, "SELECT id,revision,deleted,data,labels FROM records WHERE user_id=(SELECT id FROM users WHERE login=$1) AND NOT deleted AND labels @> $2::varchar(64)[] ORDER BY id", login, []string{label})
}
func (p *Postgres) list(ctx context.Context, query string, args ...any) ([]model.Record, error) {
	rows, e := p.pool.Query(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []model.Record{}
	for rows.Next() {
		var r model.Record
		if e = rows.Scan(&r.ID, &r.Revision, &r.Deleted, &r.Data, &r.Labels); e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// Apply serializes writes per account, rejects stale revisions and replays identical operation IDs.
// Reusing an operation ID for a different payload is a conflict. Tombstones cannot be resurrected.
func (p *Postgres) Apply(ctx context.Context, login string, m model.Mutation) (model.Record, error) {
	if e := m.Validate(); e != nil {
		return model.Record{}, e
	}
	tx, e := p.pool.Begin(ctx)
	if e != nil {
		return model.Record{}, e
	}
	defer tx.Rollback(ctx)
	var owner int64
	if e = tx.QueryRow(ctx, "SELECT id FROM users WHERE login=$1 FOR UPDATE", login).Scan(&owner); e != nil {
		return model.Record{}, e
	}
	raw, _ := json.Marshal(m)
	digest := sha256.Sum256(raw)
	var oldHash, result []byte
	e = tx.QueryRow(ctx, "SELECT request_hash,result FROM operations WHERE user_id=$1 AND id=$2", owner, m.Operation).Scan(&oldHash, &result)
	if e == nil {
		if !bytes.Equal(oldHash, digest[:]) {
			return model.Record{}, model.ErrConflict
		}
		var r model.Record
		e = json.Unmarshal(result, &r)
		r.Data = m.Record.Data
		return r, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return model.Record{}, e
	}
	var revision int64
	var deleted bool
	e = tx.QueryRow(ctx, "SELECT revision,deleted FROM records WHERE user_id=$1 AND id=$2", owner, m.Record.ID).Scan(&revision, &deleted)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return model.Record{}, e
	}
	if revision != m.Base || deleted {
		return model.Record{}, model.ErrConflict
	}
	if revision == 0 {
		var n int
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM records WHERE user_id=$1", owner).Scan(&n); e != nil {
			return model.Record{}, e
		}
		if n >= model.MaxRecords {
			return model.Record{}, model.ErrLimit
		}
	}
	var used int64
	if e = tx.QueryRow(ctx, "SELECT COALESCE(sum(octet_length(data)),0) FROM records WHERE user_id=$1 AND id<>$2", owner, m.Record.ID).Scan(&used); e != nil {
		return model.Record{}, e
	}
	if used+int64(len(m.Record.Data)) > model.MaxVaultData {
		return model.Record{}, model.ErrLimit
	}
	r := m.Record
	r.Revision = revision + 1
	_, e = tx.Exec(ctx, `INSERT INTO records(user_id,id,revision,deleted,data,labels) VALUES($1,$2,$3,$4,$5,$6)
 ON CONFLICT(user_id,id) DO UPDATE SET revision=EXCLUDED.revision,deleted=EXCLUDED.deleted,data=EXCLUDED.data,labels=EXCLUDED.labels`, owner, r.ID, r.Revision, r.Deleted, r.Data, append([]string{}, r.Labels...))
	if e != nil {
		return model.Record{}, e
	}
	receipt := r
	receipt.Data = nil
	result, _ = json.Marshal(receipt)
	if _, e = tx.Exec(ctx, "INSERT INTO operations(user_id,id,request_hash,result) VALUES($1,$2,$3,$4)", owner, m.Operation, digest[:], result); e != nil {
		return model.Record{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return model.Record{}, e
	}
	return r, nil
}
