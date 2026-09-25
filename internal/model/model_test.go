package model

import (
	"strings"
	"testing"
)

func TestSecretValidation(t *testing.T) {
	good := []Secret{{Type: "text", Title: "note", Text: "hello"}, {Type: "credentials", Title: "account", Login: "u", Password: "p"}, {Type: "binary", Title: "empty file", Filename: "empty"}, {Type: "card", Title: "bank", CardNumber: "123", CardHolder: "A", Expiry: "12/30"}}
	for _, s := range good {
		if e := s.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	bad := []Secret{{}, {Type: "other", Title: "x"}, {Type: "text", Title: "x"}, {Type: "credentials", Title: "x"}, {Type: "binary", Title: "x"}, {Type: "card", Title: "x"}, {Type: "text", Title: "x", Text: "a", Password: "leak"}, {Type: "text", Title: strings.Repeat("x", 1025), Text: "a"}, {Type: "text", Title: "x", Text: "a", Metadata: strings.Repeat("x", 65537)}}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Fatalf("accepted invalid secret: %s", s.Type)
		}
	}
}
func TestMutationValidation(t *testing.T) {
	m := Mutation{Operation: strings.Repeat("a", 32), Record: Record{ID: strings.Repeat("b", 32), Data: make([]byte, 29)}}
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Mutation){func(m *Mutation) { m.Operation = "bad" }, func(m *Mutation) { m.Record.ID = "bad" }, func(m *Mutation) { m.Base = -1 }, func(m *Mutation) { m.Record.Revision = 1 }, func(m *Mutation) { m.Record.Data = nil }, func(m *Mutation) { m.Record.Deleted = true }} {
		x := m
		change(&x)
		if x.Validate() == nil {
			t.Fatal("accepted invalid mutation")
		}
	}
	m.Base = 1
	m.Record.Deleted = true
	m.Record.Data = nil
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	if !ValidLogin("user-1") || ValidLogin("a") || ValidLogin("a b") || !ValidID(strings.Repeat("a", 32)) {
		t.Fatal("identifier rules")
	}
}

func TestPublicLabelValidation(t *testing.T) {
	for _, labels := range [][]string{{""}, {" work"}, {"work", "work"}, {strings.Repeat("x", 65)}, {string([]byte{0xff})}, make([]string, 17)} {
		if err := ValidateLabels(labels); err == nil {
			t.Fatal("invalid labels accepted")
		}
	}
	if err := ValidateLabels([]string{"work", "личное"}); err != nil {
		t.Fatal(err)
	}
	m := Mutation{Operation: strings.Repeat("a", 32), Base: 1, Record: Record{ID: strings.Repeat("b", 32), Deleted: true, Labels: []string{"work"}}}
	if err := m.Validate(); err == nil {
		t.Fatal("tombstone kept public labels")
	}
}
