// Package testutil provides isolated in-memory fixtures for transport and CLI unit tests.
package testutil

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/store"
)

// DB is a concurrency-safe Store fixture with optional injected failures.
type DB struct {
	mu       sync.Mutex
	users    map[string]store.User
	sessions map[string]session
	records  map[string]map[string]model.Record
	ops      map[string]operation
	Err      error
}
type session struct {
	login   string
	expires time.Time
}
type operation struct {
	request string
	result  model.Record
}

// NewDB returns an empty disposable fixture.
func NewDB() *DB {
	return &DB{users: map[string]store.User{}, sessions: map[string]session{}, records: map[string]map[string]model.Record{}, ops: map[string]operation{}}
}

// CreateUser inserts a unique test account.
func (d *DB) CreateUser(_ context.Context, u store.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return d.Err
	}
	if _, ok := d.users[u.Login]; ok {
		return model.ErrExists
	}
	d.users[u.Login] = u
	d.records[u.Login] = map[string]model.Record{}
	return nil
}

// User loads an account fixture.
func (d *DB) User(_ context.Context, login string) (store.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return store.User{}, d.Err
	}
	u, ok := d.users[login]
	if !ok {
		return u, model.ErrNotFound
	}
	return u, nil
}

// CreateSession inserts a token hash with expiry.
func (d *DB) CreateSession(_ context.Context, hash, login string, expires time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return d.Err
	}
	d.sessions[hash] = session{login, expires}
	return nil
}

// Session returns the owner of an active token hash.
func (d *DB) Session(_ context.Context, hash string, now time.Time) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return "", d.Err
	}
	s, ok := d.sessions[hash]
	if !ok || !s.expires.After(now) {
		return "", model.ErrNotFound
	}
	return s.login, nil
}

// DeleteSession revokes a test session.
func (d *DB) DeleteSession(_ context.Context, hash string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return d.Err
	}
	delete(d.sessions, hash)
	return nil
}

// List returns only the chosen owner's records.
func (d *DB) List(_ context.Context, login string) ([]model.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return nil, d.Err
	}
	result := []model.Record{}
	for _, r := range d.records[login] {
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// Apply emulates atomic ownership, revisions and operation replay.
func (d *DB) Apply(_ context.Context, login string, m model.Mutation) (model.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return model.Record{}, d.Err
	}
	if e := m.Validate(); e != nil {
		return model.Record{}, e
	}
	b, _ := json.Marshal(m)
	op := login + "/" + m.Operation
	if old, ok := d.ops[op]; ok {
		if old.request != string(b) {
			return model.Record{}, model.ErrConflict
		}
		return old.result, nil
	}
	old := d.records[login][m.Record.ID]
	if old.Revision != m.Base || old.Deleted {
		return model.Record{}, model.ErrConflict
	}
	if old.Revision == 0 && len(d.records[login]) >= model.MaxRecords {
		return model.Record{}, model.ErrLimit
	}
	used := 0
	for id, record := range d.records[login] {
		if id != m.Record.ID {
			used += len(record.Data)
		}
	}
	if used+len(m.Record.Data) > model.MaxVaultData {
		return model.Record{}, model.ErrLimit
	}
	r := m.Record
	r.Revision = m.Base + 1
	d.records[login][r.ID] = r
	d.ops[op] = operation{string(b), r}
	return r, nil
}

// ListByLabel returns live records matching an exact public label, ordered by ID.
func (d *DB) ListByLabel(ctx context.Context, login, label string) ([]model.Record, error) {
	if err := model.ValidateLabels([]string{label}); err != nil {
		return nil, err
	}
	records, err := d.List(ctx, login)
	if err != nil {
		return nil, err
	}
	filtered := []model.Record{}
	for _, r := range records {
		if !r.Deleted && slices.Contains(r.Labels, label) {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}
