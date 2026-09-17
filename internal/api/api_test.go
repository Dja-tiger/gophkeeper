package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/testutil"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

func request(h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func credentials(login string) model.Credentials {
	return model.Credentials{Login: login, Password: "authentication-password", Salt: make([]byte, 16), KeyCheck: make([]byte, 40)}
}
func register(t *testing.T, h http.Handler, login string) model.Session {
	t.Helper()
	w := request(h, "POST", "/v1/register", "", credentials(login))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var s model.Session
	if e := json.Unmarshal(w.Body.Bytes(), &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestUserIsolationAndSessions(t *testing.T) {
	db := testutil.NewDB()
	h := New(db)
	a := register(t, h, "alice")
	b := register(t, h, "bob")
	m := model.Mutation{Operation: vault.ID(), Record: model.Record{ID: vault.ID(), Data: make([]byte, 40)}}
	if w := request(h, "POST", "/v1/records", a.Token, m); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(h, "GET", "/v1/records", b.Token, nil); w.Code != 200 || strings.Contains(w.Body.String(), m.Record.ID) {
		t.Fatal("cross-user read", w.Body.String())
	}
	m.Operation = vault.ID()
	m.Base = 1
	if w := request(h, "POST", "/v1/records", b.Token, m); w.Code != 409 {
		t.Fatal("cross-user update", w.Code)
	}
	if w := request(h, "POST", "/v1/records", a.Token, m); w.Code != 200 {
		t.Fatal("owner update", w.Code)
	}
	m.Operation = vault.ID()
	if w := request(h, "POST", "/v1/records", a.Token, m); w.Code != 409 {
		t.Fatal("stale update accepted")
	}
	if w := request(h, "POST", "/v1/logout", a.Token, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/v1/records", a.Token, nil); w.Code != 401 {
		t.Fatal("revoked token accepted")
	}
	db.CreateSession(context.Background(), digest(a.Token), "alice", time.Now().Add(-time.Hour))
	if w := request(h, "GET", "/v1/records", a.Token, nil); w.Code != 401 {
		t.Fatal("expired token accepted")
	}
	if w := request(h, "POST", "/v1/login", "", credentials("alice")); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/v1/register", "", credentials("alice")); w.Code != 409 {
		t.Fatal(w.Code)
	}
	c := credentials("alice")
	c.Password = "incorrect-password"
	if w := request(h, "POST", "/v1/login", "", c); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/v1/login", "", credentials("missing")); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestMalformedRequests(t *testing.T) {
	h := New(testutil.NewDB())
	s := register(t, h, "alice")
	cases := []struct {
		method, path, body, content, auth string
		status                            int
	}{
		{"POST", "/v1/register", "{}", "application/json", "", 400}, {"POST", "/v1/login", "{}", "application/json", "", 401},
		{"POST", "/v1/login", "{", "application/json", "", 400}, {"POST", "/v1/login", "{} {}", "application/json", "", 400},
		{"POST", "/v1/login", "{}", "text/plain", "", 415}, {"POST", "/v1/login", `{"unknown":true}`, "application/json", "", 400},
		{"GET", "/v1/records", "", "", "B", 401}, {"GET", "/v1/records", "", "", "", 401},
		{"POST", "/v1/records", "{}", "application/json", "Bearer " + s.Token, 400},
		{"GET", "/healthz", "", "", "", 200}, {"POST", "/v1/login", strings.Repeat(" ", 9000), "application/json", "", 400},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		r.Header.Set("Content-Type", c.content)
		r.Header.Set("Authorization", c.auth)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Errorf("%s: got %d want %d", c.path, w.Code, c.status)
		}
	}
}
func TestStorageFailureAndLimits(t *testing.T) {
	db := testutil.NewDB()
	h := New(db)
	s := register(t, h, "alice")
	db.Err = errors.New("database password must not leak")
	for _, c := range []struct {
		path, token string
		body        any
	}{{"/v1/register", "", credentials("other")}, {"/v1/login", "", credentials("alice")}, {"/v1/records", s.Token, nil}} {
		w := request(h, "POST", c.path, c.token, c.body)
		if w.Code != 500 || strings.Contains(w.Body.String(), "must not leak") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	server := &Server{db: db, authSlots: make(chan struct{}, 1), attempts: map[string]attempt{}}
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		if server.limited(w, httptest.NewRequest("POST", "/", nil), "alice") {
			t.Fatal("early limit")
		}
		<-server.authSlots
	}
	w := httptest.NewRecorder()
	if !server.limited(w, httptest.NewRequest("POST", "/", nil), "alice") || w.Code != 429 {
		t.Fatal("limit missing")
	}
	server.authSlots <- struct{}{}
	w = httptest.NewRecorder()
	if !server.limited(w, httptest.NewRequest("POST", "/", nil), "other") {
		t.Fatal("concurrency cap missing")
	}
}
