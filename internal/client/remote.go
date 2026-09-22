// Package client implements the secure HTTP client, encrypted local cache and synchronization.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Dja-tiger/gophkeeper/internal/model"
)

// Remote communicates with one server. Token is never sent across redirects.
type Remote struct {
	URL   string
	Token string
	HTTP  *http.Client
}

// NewRemote enforces HTTPS. Development HTTP is allowed only for literal loopback hosts.
// caPEM optionally adds a local CA to the system trust store; verification is never disabled.
func NewRemote(address string, allowHTTP bool, caPEM []byte) (*Remote, error) {
	u, e := url.Parse(address)
	if e != nil {
		return nil, e
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("server must be an origin URL without credentials, path, query or fragment")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && allowHTTP && loopback) {
		return nil, errors.New("HTTPS required; --dev-http allows loopback HTTP only")
	}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if len(caPEM) > 0 && !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &Remote{URL: strings.TrimRight(address, "/"), HTTP: &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") }}}, nil
}

// Error describes an API failure without exposing server response bodies or secrets.
type Error struct{ Status int }

// Error reports an actionable status message.
func (e *Error) Error() string {
	switch e.Status {
	case 401:
		return "session expired or invalid credentials; log in again"
	case 409:
		return "conflict: login exists or record changed"
	case 429:
		return "too many attempts; retry later"
	}
	return fmt.Sprintf("server returned HTTP %d", e.Status)
}
func (r *Remote) call(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, r.URL+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	resp, e := r.HTTP.Do(req)
	if e != nil {
		return fmt.Errorf("request failed: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{resp.StatusCode}
	}
	if output == nil {
		return nil
	}
	reader := &io.LimitedReader{R: resp.Body, N: (100 << 20) + 1}
	decoder := json.NewDecoder(reader)
	if e = decoder.Decode(output); e != nil {
		return errors.New("invalid JSON response")
	}
	if e = decoder.Decode(&struct{}{}); e != io.EOF || reader.N == 0 {
		return errors.New("response must contain exactly one JSON value within the size limit")
	}
	return nil
}

// Register creates a user and returns its first session.
func (r *Remote) Register(ctx context.Context, c model.Credentials) (model.Session, error) {
	var s model.Session
	e := r.call(ctx, "POST", "/v1/register", c, &s)
	return s, e
}

// Login authenticates and returns the user's vault parameters.
func (r *Remote) Login(ctx context.Context, c model.Credentials) (model.Session, error) {
	var s model.Session
	e := r.call(ctx, "POST", "/v1/login", c, &s)
	return s, e
}

// Logout revokes the current bearer token.
func (r *Remote) Logout(ctx context.Context) error {
	return r.call(ctx, "POST", "/v1/logout", nil, nil)
}

// List downloads a complete owner-scoped snapshot, including tombstones.
func (r *Remote) List(ctx context.Context) ([]model.Record, error) {
	var records []model.Record
	e := r.call(ctx, "GET", "/v1/records", nil, &records)
	if e == nil && records == nil {
		e = errors.New("snapshot must be a JSON array")
	}
	return records, e
}

// Apply submits an idempotent mutation and returns the assigned revision.
func (r *Remote) Apply(ctx context.Context, m model.Mutation) (model.Record, error) {
	var v model.Record
	e := r.call(ctx, "POST", "/v1/records", m, &v)
	return v, e
}
