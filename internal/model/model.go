// Package model defines the versioned wire contract and client-side secret types.
package model

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxData is the largest encrypted record accepted by the service (12 MiB).
const MaxData = 12 << 20

// MaxFile is the largest plaintext binary payload (8 MiB).
const MaxFile = 8 << 20

// MaxVaultData limits active encrypted data per account to 64 MiB.
const MaxVaultData = 64 << 20

// MaxRecords bounds each user's snapshot, including deletion tombstones.
const MaxRecords = 1000

// ErrConflict indicates that another client changed a record since it was read.
var ErrConflict = errors.New("record changed on another client; sync and resolve the conflict")

// ErrNotFound indicates an absent resource in the current owner's namespace.
var ErrNotFound = errors.New("not found")

// ErrExists indicates an already registered login.
var ErrExists = errors.New("login already registered")

// ErrLimit indicates that an account has reached its record limit.
var ErrLimit = errors.New("account record limit reached")

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var login = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,64}$`)

// ValidID reports whether id is a 128-bit lowercase hexadecimal identifier.
func ValidID(id string) bool { return identifier.MatchString(id) }

// ValidLogin restricts account names to 3–64 ASCII letters, digits, dots, dashes and underscores.
func ValidLogin(s string) bool { return login.MatchString(s) }

// Secret is decrypted only by clients. Type is credentials, text, binary or card.
// Metadata is arbitrary free-form text. Unused type-specific fields must be empty.
type Secret struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Metadata   string `json:"metadata,omitempty"`
	Login      string `json:"login,omitempty"`
	Password   string `json:"password,omitempty"`
	Text       string `json:"text,omitempty"`
	Binary     []byte `json:"binary,omitempty"`
	Filename   string `json:"filename,omitempty"`
	CardNumber string `json:"card_number,omitempty"`
	CardHolder string `json:"card_holder,omitempty"`
	Expiry     string `json:"expiry,omitempty"`
	CVV        string `json:"cvv,omitempty"`
}

// Validate checks required fields and size limits without imposing a bank-specific card format.
func (s Secret) Validate() error {
	if s.Title == "" || len(s.Title) > 1024 || len(s.Metadata) > 65536 {
		return errors.New("title required (up to 1024 bytes); metadata limited to 64 KiB")
	}
	switch s.Type {
	case "credentials":
		if s.Login == "" || s.Password == "" {
			return errors.New("login and password required")
		}
	case "text":
		if s.Text == "" {
			return errors.New("text required")
		}
	case "binary":
		if s.Filename == "" || len(s.Binary) > MaxFile {
			return errors.New("filename required; binary limit is 8 MiB")
		}
	case "card":
		if s.CardNumber == "" || s.CardHolder == "" || s.Expiry == "" {
			return errors.New("card number, holder and expiry required")
		}
	default:
		return errors.New("type must be credentials, text, binary or card")
	}
	if s.Type != "credentials" && (s.Login != "" || s.Password != "") || s.Type != "text" && s.Text != "" || s.Type != "binary" && (len(s.Binary) > 0 || s.Filename != "") || s.Type != "card" && (s.CardNumber != "" || s.CardHolder != "" || s.Expiry != "" || s.CVV != "") {
		return errors.New("fields do not match the secret type")
	}
	return nil
}

// Record contains encrypted data, optional public labels, an owner-local revision and a deletion marker.
type Record struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Deleted  bool   `json:"deleted"`
	Data     []byte `json:"data,omitempty"`
	// Labels are optional public search tags, visible to the server; never put secrets here.
	Labels []string `json:"labels,omitempty"`
}

// Mutation carries an idempotency key and the expected revision (zero for creation).
type Mutation struct {
	Operation string `json:"operation"`
	Base      int64  `json:"base"`
	Record    Record `json:"record"`
}

// Validate rejects malformed writes before they reach persistence.
func (m Mutation) Validate() error {
	if !ValidID(m.Operation) || !ValidID(m.Record.ID) || m.Base < 0 || m.Base >= 1<<62 || m.Record.Revision != 0 {
		return errors.New("invalid mutation identifier or revision")
	}
	if err := ValidateLabels(m.Record.Labels); err != nil {
		return err
	}
	if m.Record.Deleted {
		if len(m.Record.Data) != 0 || len(m.Record.Labels) != 0 || m.Base == 0 {
			return errors.New("deletion requires an existing record and no data")
		}
	} else if len(m.Record.Data) < 29 || len(m.Record.Data) > MaxData {
		return errors.New("invalid encrypted data size")
	}
	return nil
}

// Credentials is the authentication request. Vault fields are required only during registration.
type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Salt     []byte `json:"salt,omitempty"`
	KeyCheck []byte `json:"key_check,omitempty"`
}

// Session returns the bearer token and immutable client-side vault parameters.
type Session struct {
	Token    string `json:"token"`
	Login    string `json:"login"`
	Salt     []byte `json:"salt"`
	KeyCheck []byte `json:"key_check"`
}

// ValidateLabels checks at most 16 unique public labels of 1–64 UTF-8 bytes, without surrounding whitespace.
func ValidateLabels(labels []string) error {
	if len(labels) > 16 {
		return errors.New("at most 16 public labels allowed")
	}
	seen := make(map[string]bool, len(labels))
	for _, label := range labels {
		if label == "" || len(label) > 64 || !utf8.ValidString(label) || strings.TrimSpace(label) != label {
			return errors.New("public labels must be 1–64 UTF-8 bytes without surrounding whitespace")
		}
		if seen[label] {
			return errors.New("duplicate public label")
		}
		seen[label] = true
	}
	return nil
}
