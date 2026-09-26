package testutil

import (
	"context"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/store"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func TestListOrdersRecordsByID(t *testing.T) {
	ctx := context.Background()
	db := NewDB()
	if err := db.CreateUser(ctx, store.User{Login: "alice"}); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if _, err := db.Apply(ctx, "alice", model.Mutation{Operation: vault.ID(), Record: model.Record{ID: vault.ID(), Data: make([]byte, 40)}}); err != nil {
			t.Fatal(err)
		}
	}
	for range 10 {
		records, err := db.List(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(records); i++ {
			if records[i-1].ID >= records[i].ID {
				t.Fatal("records are not sorted")
			}
		}
	}
}
