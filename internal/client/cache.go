package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

// Cache stores only encrypted records and vault parameters. The token is protected by file permissions.
// One cache belongs to exactly one server and login; callers must lock it before read-modify-write.
type Cache struct {
	Version int                       `json:"version"`
	Server  string                    `json:"server"`
	Session model.Session             `json:"session"`
	Records map[string]model.Record   `json:"records"`
	Pending map[string]model.Mutation `json:"pending"`
}

// NewCache initializes an empty version-1 cache bound to an authenticated account.
func NewCache(server string, s model.Session) *Cache {
	return &Cache{Version: 1, Server: server, Session: s, Records: map[string]model.Record{}, Pending: map[string]model.Mutation{}}
}

// Load reads a cache. Unsupported or malformed cache formats are rejected.
func Load(path string) (*Cache, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var c Cache
	if e = json.Unmarshal(b, &c); e != nil {
		return nil, e
	}
	if e = c.validate(); e != nil {
		return nil, e
	}
	return &c, nil
}

func (c *Cache) validate() error {
	if c.Version != 1 || c.Server == "" || !model.ValidLogin(c.Session.Login) || len(c.Session.Salt) != 16 || len(c.Session.KeyCheck) < 29 || len(c.Session.KeyCheck) > 256 || c.Records == nil || c.Pending == nil {
		return errors.New("invalid cache format")
	}
	for id, record := range c.Records {
		if !model.ValidID(id) || record.ID != id || record.Revision < 0 || record.Revision > 1<<62 {
			return errors.New("invalid cache record identity or revision")
		}
		if record.Deleted && len(record.Data) != 0 || !record.Deleted && (len(record.Data) < 29 || len(record.Data) > model.MaxData) {
			return errors.New("invalid cache record data")
		}
		if _, pending := c.Pending[id]; !pending && (record.Revision == 0 || record.Deleted && record.Revision < 2) {
			return errors.New("cache record is missing its pending operation")
		}
	}
	operations := make(map[string]bool, len(c.Pending))
	for id, m := range c.Pending {
		record, exists := c.Records[id]
		if m.Validate() != nil || id != m.Record.ID || !exists || record.Deleted != m.Record.Deleted || !bytes.Equal(record.Data, m.Record.Data) || operations[m.Operation] {
			return errors.New("cache pending operation does not match its record")
		}
		operations[m.Operation] = true
	}
	return nil
}

// Save writes through a private temporary file and atomically replaces the cache.
func (c *Cache) Save(path string) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".vault-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}

// Lock prevents concurrent CLI processes from overwriting the same cache.
// A stale lock after a killed process must be removed manually after checking no client is running.
func Lock(path string) (func(), error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, fmt.Errorf("cache is locked or inaccessible: %w", e)
	}
	fmt.Fprintln(f, os.Getpid())
	f.Close()
	return func() { _ = os.Remove(path + ".lock") }, nil
}

// Unlock derives and verifies the vault key without any network request.
func (c *Cache) Unlock(password string) ([]byte, error) {
	key, e := vault.Derive(password, c.Session.Salt)
	if e != nil {
		return nil, e
	}
	p, e := vault.Open(key, c.Session.KeyCheck, "gophkeeper/v1/check/"+c.Session.Login)
	if e != nil || string(p) != "gophkeeper-vault-v1" {
		clear(key)
		return nil, errors.New("wrong vault password or damaged key check")
	}
	return key, nil
}

// VaultParameters generates the salt and encrypted key check used once during registration.
func VaultParameters(login, password string) ([]byte, []byte, error) {
	salt := vault.Random(16)
	key, e := vault.Derive(password, salt)
	if e != nil {
		return nil, nil, e
	}
	defer clear(key)
	check, e := vault.Seal(key, []byte("gophkeeper-vault-v1"), "gophkeeper/v1/check/"+login)
	return salt, check, e
}
func (c *Cache) identity(id string) string {
	return "gophkeeper/v1/record/" + c.Session.Login + "/" + id
}

// Read decrypts a local record; deleted or absent entries return model.ErrNotFound.
func (c *Cache) Read(key []byte, id string) (model.Secret, error) {
	r, ok := c.Records[id]
	if !ok || r.Deleted {
		return model.Secret{}, model.ErrNotFound
	}
	b, e := vault.Open(key, r.Data, c.identity(id))
	if e != nil {
		return model.Secret{}, e
	}
	var s model.Secret
	if e = json.Unmarshal(b, &s); e != nil {
		return model.Secret{}, errors.New("invalid decrypted secret JSON")
	}
	return s, s.Validate()
}

// Put creates (empty id) or replaces a record and queues its encrypted mutation.
// Sync pending work before editing that record again, preserving retry idempotency after network failure.
func (c *Cache) Put(key []byte, id string, s model.Secret) (string, error) {
	if e := s.Validate(); e != nil {
		return "", e
	}
	if id == "" {
		id = vault.ID()
	} else {
		if !model.ValidID(id) {
			return "", errors.New("invalid ID")
		}
		if _, ok := c.Records[id]; !ok {
			return "", model.ErrNotFound
		}
	}
	if _, ok := c.Pending[id]; ok {
		return "", errors.New("record has a pending change; sync or resolve it first")
	}
	old := c.Records[id]
	if old.Deleted {
		return "", model.ErrNotFound
	}
	b, e := json.Marshal(s)
	if e != nil {
		return "", e
	}
	encrypted, e := vault.Seal(key, b, c.identity(id))
	if e != nil {
		return "", e
	}
	if len(encrypted) > model.MaxData {
		return "", errors.New("record exceeds encrypted size limit")
	}
	m := model.Mutation{Operation: vault.ID(), Base: old.Revision, Record: model.Record{ID: id, Data: encrypted}}
	c.Pending[id] = m
	r := m.Record
	r.Revision = old.Revision
	c.Records[id] = r
	return id, nil
}

// Delete queues a tombstone for a synchronized record.
func (c *Cache) Delete(id string) error {
	if _, ok := c.Pending[id]; ok {
		return errors.New("record has a pending change; sync or resolve it first")
	}
	old, ok := c.Records[id]
	if !ok || old.Deleted {
		return model.ErrNotFound
	}
	m := model.Mutation{Operation: vault.ID(), Base: old.Revision, Record: model.Record{ID: id, Deleted: true}}
	c.Pending[id] = m
	r := m.Record
	r.Revision = old.Revision
	c.Records[id] = r
	return nil
}

// Transport is the record synchronization subset of the remote API.
type Transport interface {
	List(context.Context) ([]model.Record, error)
	Apply(context.Context, model.Mutation) (model.Record, error)
}

// Sync pushes deletions first to free data quota, then other operations, ordered by ID within each group.
// It pulls a full snapshot once every pending operation has been acknowledged.
// On failure, unsent and ambiguous writes remain pending; operation IDs make retries safe.
func (c *Cache) Sync(ctx context.Context, r Transport) error {
	ids := make([]string, 0, len(c.Pending))
	for id := range c.Pending {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := c.Pending[ids[i]].Record.Deleted, c.Pending[ids[j]].Record.Deleted
		if a != b {
			return a
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids {
		m := c.Pending[id]
		record, e := r.Apply(ctx, m)
		if e != nil {
			return fmt.Errorf("sync %s: %w", id, e)
		}
		if record.ID != id || record.Revision != m.Base+1 || record.Deleted != m.Record.Deleted || !bytes.Equal(record.Data, m.Record.Data) {
			return fmt.Errorf("sync %s: invalid mutation acknowledgement; change remains pending", id)
		}
		c.Records[id] = record
		delete(c.Pending, id)
	}
	records, e := r.List(ctx)
	if e != nil {
		return e
	}
	next, e := validateSnapshot(records)
	if e != nil {
		return e
	}
	c.Records = next
	return nil
}

func validateSnapshot(records []model.Record) (map[string]model.Record, error) {
	if records == nil {
		return nil, errors.New("snapshot must be a JSON array")
	}
	if len(records) > model.MaxRecords {
		return nil, errors.New("snapshot exceeds record limit")
	}
	next := make(map[string]model.Record, len(records))
	total := 0
	for _, record := range records {
		if !model.ValidID(record.ID) || record.Revision < 1 || record.Revision > 1<<62 {
			return nil, errors.New("invalid snapshot record")
		}
		if record.Deleted {
			if record.Revision < 2 || len(record.Data) != 0 {
				return nil, errors.New("invalid snapshot tombstone")
			}
		} else if len(record.Data) < 29 || len(record.Data) > model.MaxData {
			return nil, errors.New("invalid snapshot encrypted data size")
		}
		if _, exists := next[record.ID]; exists {
			return nil, errors.New("duplicate snapshot ID")
		}
		total += len(record.Data)
		if total > model.MaxVaultData {
			return nil, errors.New("snapshot exceeds data quota")
		}
		next[record.ID] = record
	}
	return next, nil
}

// Resolve explicitly discards a pending change in favor of the server, or rebases it on the remote revision.
// Keeping a local edit over a remote deletion creates a new record ID and re-encrypts its identity binding.
func (c *Cache) Resolve(ctx context.Context, r Transport, key []byte, id, choice string) error {
	m, ok := c.Pending[id]
	if !ok {
		return errors.New("no pending change for this ID")
	}
	if choice != "local" && choice != "remote" {
		return errors.New("choose local or remote")
	}
	records, e := r.List(ctx)
	if e != nil {
		return e
	}
	next, e := validateSnapshot(records)
	if e != nil {
		return e
	}
	remote, found := next[id]
	if choice == "remote" {
		delete(c.Pending, id)
		if found {
			c.Records[id] = remote
		} else {
			delete(c.Records, id)
		}
		return nil
	}
	if found && remote.Deleted {
		if m.Record.Deleted {
			delete(c.Pending, id)
			c.Records[id] = remote
			return nil
		}
		secret, e := c.Read(key, id)
		if e != nil {
			return e
		}
		delete(c.Pending, id)
		c.Records[id] = remote
		_, e = c.Put(key, "", secret)
		return e
	}
	if !found && m.Record.Deleted {
		delete(c.Pending, id)
		delete(c.Records, id)
		return nil
	}
	m.Base = remote.Revision
	m.Operation = vault.ID()
	c.Pending[id] = m
	return nil
}
