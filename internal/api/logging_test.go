package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/store"
	"github.com/Dja-tiger/gophkeeper/internal/testutil"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

type failingStore struct {
	store.Store
	operation string
	err       error
}

func (s failingStore) CreateUser(ctx context.Context, u store.User) error {
	if s.operation == "create-user" {
		return s.err
	}
	return s.Store.CreateUser(ctx, u)
}
func (s failingStore) User(ctx context.Context, login string) (store.User, error) {
	if s.operation == "user" {
		return store.User{}, s.err
	}
	return s.Store.User(ctx, login)
}
func (s failingStore) CreateSession(ctx context.Context, hash, login string, expiry time.Time) error {
	if s.operation == "create-session" {
		return s.err
	}
	return s.Store.CreateSession(ctx, hash, login, expiry)
}
func (s failingStore) Session(ctx context.Context, hash string, now time.Time) (string, error) {
	if s.operation == "session" {
		return "", s.err
	}
	return s.Store.Session(ctx, hash, now)
}
func (s failingStore) DeleteSession(ctx context.Context, hash string) error {
	if s.operation == "delete-session" {
		return s.err
	}
	return s.Store.DeleteSession(ctx, hash)
}
func (s failingStore) List(ctx context.Context, login string) ([]model.Record, error) {
	if s.operation == "list" {
		return nil, s.err
	}
	return s.Store.List(ctx, login)
}
func (s failingStore) Apply(ctx context.Context, login string, m model.Mutation) (model.Record, error) {
	if s.operation == "apply" {
		return model.Record{}, s.err
	}
	return s.Store.Apply(ctx, login, m)
}

func TestInternalErrorsAreLoggedWithoutRequestSecrets(t *testing.T) {
	db := testutil.NewDB()
	session := register(t, New(db, slog.New(slog.NewTextHandler(io.Discard, nil))), "alice")
	failure := errors.New("storage failure trace")
	for _, tc := range []struct {
		operation, method, path string
		body                    any
	}{
		{"create-user", "POST", "/v1/register", credentials("other")},
		{"user", "POST", "/v1/login", credentials("alice")},
		{"create-session", "POST", "/v1/login", credentials("alice")},
		{"session", "GET", "/v1/records", nil},
		{"delete-session", "POST", "/v1/logout", nil},
		{"list", "GET", "/v1/records", nil},
		{"apply", "POST", "/v1/records", model.Mutation{Operation: vault.ID(), Record: model.Record{ID: vault.ID(), Data: bytes.Repeat([]byte("private-record"), 3)}}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			var logs bytes.Buffer
			h := New(failingStore{Store: db, operation: tc.operation, err: failure}, slog.New(slog.NewJSONHandler(&logs, nil)))
			response := request(h, tc.method, tc.path, session.Token, tc.body)
			if response.Code != 500 || strings.Contains(response.Body.String(), failure.Error()) {
				t.Fatal("internal error exposed or not returned", response.Code)
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["level"] != "ERROR" || entry["error"] != failure.Error() || entry["path"] != tc.path {
				t.Fatal("missing error context", entry)
			}
			for _, secret := range []string{session.Token, credentials("alice").Password, "private-record"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("request secret logged")
				}
			}
		})
	}
}
