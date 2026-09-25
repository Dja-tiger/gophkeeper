package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

type acknowledgement struct{ record model.Record }

func (a acknowledgement) Apply(context.Context, model.Mutation) (model.Record, error) {
	return a.record, nil
}
func (a acknowledgement) List(context.Context) ([]model.Record, error) { return []model.Record{}, nil }

func TestInvalidAcknowledgementPreservesPending(t *testing.T) {
	key := vault.Random(32)
	for _, kind := range []string{"empty", "id", "revision", "deleted", "data"} {
		t.Run(kind, func(t *testing.T) {
			c := NewCache("https://example.com", model.Session{Login: "alice"})
			id, err := c.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "unsent"})
			if err != nil {
				t.Fatal(err)
			}
			m := c.Pending[id]
			old := c.Records[id]
			ack := m.Record
			ack.Revision = m.Base + 1
			switch kind {
			case "empty":
				ack = model.Record{}
			case "id":
				ack.ID = vault.ID()
			case "revision":
				ack.Revision++
			case "deleted":
				ack.Deleted = true
			case "data":
				ack.Data = make([]byte, len(ack.Data))
			}
			if err = c.Sync(context.Background(), acknowledgement{ack}); err == nil {
				t.Fatal("invalid acknowledgement accepted")
			}
			if !reflect.DeepEqual(c.Pending[id], m) || !reflect.DeepEqual(c.Records[id], old) {
				t.Fatal("unacknowledged change lost")
			}
		})
	}
}

func TestResolveRejectsInvalidSnapshot(t *testing.T) {
	key := vault.Random(32)
	for _, choice := range []string{"local", "remote"} {
		for _, kind := range []string{"null", "duplicate", "revision", "data", "tombstone", "size"} {
			t.Run(choice+"/"+kind, func(t *testing.T) {
				c := NewCache("https://example.com", model.Session{Login: "alice"})
				id, err := c.Put(key, "", model.Secret{Type: "text", Title: "note", Text: "unsent"})
				if err != nil {
					t.Fatal(err)
				}
				valid := c.Records[id]
				valid.Revision = 1
				records := []model.Record{valid}
				switch kind {
				case "null":
					records = nil
				case "duplicate":
					records = append(records, valid)
				case "revision":
					records[0].Revision = 0
				case "data":
					records[0].Data = nil
				case "tombstone":
					records[0].Deleted = true
				case "size":
					records[0].Data = make([]byte, model.MaxData+1)
				}
				before, _ := json.Marshal(c)
				if err = c.Resolve(context.Background(), snapshot{records}, key, id, choice); err == nil {
					t.Fatal("invalid snapshot accepted")
				}
				after, _ := json.Marshal(c)
				if !bytes.Equal(before, after) {
					t.Fatal("resolution changed cache after invalid snapshot")
				}
				clean := NewCache(c.Server, c.Session)
				clean.Records[id] = valid
				if err = clean.Sync(context.Background(), snapshot{records}); err == nil {
					t.Fatal("sync accepted invalid snapshot")
				}
				if !reflect.DeepEqual(clean.Records[id], valid) {
					t.Fatal("sync replaced valid cache")
				}
			})
		}
	}
}

func TestRemoteRejectsIncompleteJSON(t *testing.T) {
	for _, body := range []string{"null", "[] {}", "[] garbage", "[]"} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer server.Close()
			r, err := NewRemote(server.URL, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.List(context.Background())
			if (err == nil) != (body == "[]") {
				t.Fatalf("unexpected JSON validation result: %v", err)
			}
		})
	}
}
