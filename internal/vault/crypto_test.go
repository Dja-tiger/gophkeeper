package vault

import (
	"bytes"
	"testing"
)

func TestDerive(t *testing.T) {
	salt := Random(16)
	a, e := Derive("long-master-password", salt)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Derive("long-master-password", salt)
	if !bytes.Equal(a, b) {
		t.Fatal("unstable key")
	}
	c, _ := Derive("long-master-password", Random(16))
	if bytes.Equal(a, c) {
		t.Fatal("salt ignored")
	}
	for _, s := range []struct {
		p string
		s []byte
	}{{"short", salt}, {"long-master-password", nil}} {
		if _, e = Derive(s.p, s.s); e == nil {
			t.Fatal("invalid parameters accepted")
		}
	}
}
func TestAuthenticatedEncryption(t *testing.T) {
	key := Random(32)
	message := []byte("private content")
	sealed, e := Seal(key, message, "alice/record")
	if e != nil {
		t.Fatal(e)
	}
	again, _ := Seal(key, message, "alice/record")
	if bytes.Equal(sealed, again) || bytes.Contains(sealed, message) {
		t.Fatal("nonce/plaintext failure")
	}
	got, e := Open(key, sealed, "alice/record")
	if e != nil || !bytes.Equal(got, message) {
		t.Fatal("roundtrip", e)
	}
	for _, tc := range []struct {
		k, b []byte
		aad  string
	}{{Random(32), sealed, "alice/record"}, {key, sealed, "bob/record"}, {key, sealed[:4], "alice/record"}, {nil, sealed, "alice/record"}} {
		if _, e = Open(tc.k, tc.b, tc.aad); e == nil {
			t.Fatal("unauthenticated data accepted")
		}
	}
	sealed[len(sealed)-1] ^= 1
	if _, e = Open(key, sealed, "alice/record"); e == nil {
		t.Fatal("tampering accepted")
	}
	if _, e = Seal(nil, message, "x"); e == nil {
		t.Fatal("bad key accepted")
	}
	if len(ID()) != 32 {
		t.Fatal("ID size")
	}
}
