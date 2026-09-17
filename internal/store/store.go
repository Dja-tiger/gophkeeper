// Package store persists users, expiring sessions and owner-scoped encrypted records.
package store

import (
	"context"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/model"
)

// User contains a bcrypt authentication hash and opaque client vault parameters.
type User struct {
	Login    string
	Hash     []byte
	Salt     []byte
	KeyCheck []byte
}

// Store is the persistence contract. Apply atomically enforces revision checks and idempotency.
// Every record operation is scoped to the authenticated login, never a login from the request body.
type Store interface {
	CreateUser(context.Context, User) error
	User(context.Context, string) (User, error)
	CreateSession(context.Context, string, string, time.Time) error
	Session(context.Context, string, time.Time) (string, error)
	DeleteSession(context.Context, string) error
	List(context.Context, string) ([]model.Record, error)
	Apply(context.Context, string, model.Mutation) (model.Record, error)
}
