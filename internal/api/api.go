// Package api serves the authenticated version-1 HTTP API over a TLS transport.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Dja-tiger/gophkeeper/internal/model"
	"github.com/Dja-tiger/gophkeeper/internal/store"
	"github.com/Dja-tiger/gophkeeper/internal/vault"
)

// Server routes requests to persistence and limits concurrent expensive password checks.
type Server struct {
	db        store.Store
	authSlots chan struct{}
	mu        sync.Mutex
	attempts  map[string]attempt
}
type attempt struct {
	count int
	reset time.Time
}

// New builds an HTTP handler. The caller is responsible for TLS and transport timeouts.
func New(db store.Store) http.Handler {
	s := &Server{db: db, authSlots: make(chan struct{}, 4), attempts: map[string]attempt{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("POST /v1/login", s.login)
	mux.HandleFunc("POST /v1/logout", s.auth(s.logout))
	mux.HandleFunc("GET /v1/records", s.auth(s.list))
	mux.HandleFunc("POST /v1/records", s.auth(s.apply))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	write(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "application/json required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid or oversized JSON")
		return false
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		fail(w, 400, "one JSON object required")
		return false
	}
	return true
}
func digest(token string) string { h := sha256.Sum256([]byte(token)); return hex.EncodeToString(h[:]) }
func (s *Server) limited(w http.ResponseWriter, r *http.Request, login string) bool {
	s.mu.Lock()
	now := time.Now()
	for k, a := range s.attempts {
		if now.After(a.reset) {
			delete(s.attempts, k)
		}
	}
	// A global cap bounds limiter memory; per-login limiting also applies behind proxies.
	a := s.attempts[login]
	if a.reset.IsZero() {
		a.reset = now.Add(time.Minute)
	}
	a.count++
	if len(s.attempts) >= 10000 || a.count > 10 {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "too many authentication attempts")
		return true
	}
	s.attempts[login] = a
	s.mu.Unlock()
	select {
	case s.authSlots <- struct{}{}:
		return false
	default:
		fail(w, 429, "authentication busy")
		return true
	}
}
func valid(c model.Credentials) bool {
	return model.ValidLogin(c.Login) && len(c.Password) >= 12 && len(c.Password) <= 72
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var c model.Credentials
	if !decode(w, r, &c, 8192) {
		return
	}
	if !valid(c) || len(c.Salt) != 16 || len(c.KeyCheck) < 29 || len(c.KeyCheck) > 256 {
		fail(w, 400, "invalid login, password (12–72 bytes), salt or key check")
		return
	}
	if s.limited(w, r, c.Login) {
		return
	}
	defer func() { <-s.authSlots }()
	hash, e := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	if e != nil {
		fail(w, 500, "authentication failed")
		return
	}
	u := store.User{Login: c.Login, Hash: hash, Salt: c.Salt, KeyCheck: c.KeyCheck}
	if e = s.db.CreateUser(r.Context(), u); e != nil {
		if errors.Is(e, model.ErrExists) {
			fail(w, 409, "login already registered")
		} else {
			fail(w, 500, "registration failed")
		}
		return
	}
	s.session(w, r, u, 201)
}

var dummyHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-authentication-password"), bcrypt.DefaultCost)
	return h
}()

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var c model.Credentials
	if !decode(w, r, &c, 8192) {
		return
	}
	if !valid(c) {
		fail(w, 401, "invalid credentials")
		return
	}
	if s.limited(w, r, c.Login) {
		return
	}
	defer func() { <-s.authSlots }()
	u, e := s.db.User(r.Context(), c.Login)
	if e != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(c.Password))
		if errors.Is(e, model.ErrNotFound) {
			fail(w, 401, "invalid credentials")
		} else {
			fail(w, 500, "authentication unavailable")
		}
		return
	}
	if bcrypt.CompareHashAndPassword(u.Hash, []byte(c.Password)) != nil {
		fail(w, 401, "invalid credentials")
		return
	}
	s.session(w, r, u, 200)
}
func (s *Server) session(w http.ResponseWriter, r *http.Request, u store.User, status int) {
	token := hex.EncodeToString(vault.Random(32))
	if e := s.db.CreateSession(r.Context(), digest(token), u.Login, time.Now().Add(24*time.Hour)); e != nil {
		fail(w, 500, "session creation failed")
		return
	}
	write(w, status, model.Session{Token: token, Login: u.Login, Salt: u.Salt, KeyCheck: u.KeyCheck})
}

type authenticated func(http.ResponseWriter, *http.Request, string, string)

func (s *Server) auth(next authenticated) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || len(token) != 64 {
			fail(w, 401, "authentication required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		login, e := s.db.Session(ctx, digest(token), time.Now())
		if e != nil {
			if errors.Is(e, model.ErrNotFound) {
				fail(w, 401, "session expired or revoked")
			} else {
				fail(w, 500, "authentication unavailable")
			}
			return
		}
		next(w, r, login, digest(token))
	}
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, login, hash string) {
	if e := s.db.DeleteSession(r.Context(), hash); e != nil {
		fail(w, 500, "logout failed")
		return
	}
	write(w, 200, map[string]bool{"ok": true})
}
func (s *Server) list(w http.ResponseWriter, r *http.Request, login, hash string) {
	items, e := s.db.List(r.Context(), login)
	if e != nil {
		fail(w, 500, "snapshot unavailable")
		return
	}
	write(w, 200, items)
}
func (s *Server) apply(w http.ResponseWriter, r *http.Request, login, hash string) {
	var m model.Mutation
	if !decode(w, r, &m, 17<<20) {
		return
	}
	if e := m.Validate(); e != nil {
		fail(w, 400, e.Error())
		return
	}
	result, e := s.db.Apply(r.Context(), login, m)
	if e != nil {
		switch {
		case errors.Is(e, model.ErrConflict):
			fail(w, 409, "revision or operation conflict")
		case errors.Is(e, model.ErrLimit):
			fail(w, 422, "account record limit reached")
		default:
			fail(w, 500, "write failed")
		}
		return
	}
	write(w, 200, result)
}
