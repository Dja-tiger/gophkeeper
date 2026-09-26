// Package vault implements versioned Argon2id key derivation and AES-256-GCM encryption.
// Passwords and derived keys never leave the client.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
)

// ID creates a random 128-bit identifier for records and idempotent operations.
func ID() string { return hex.EncodeToString(Random(16)) }

// Random returns n cryptographically secure random bytes.
func Random(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// Derive uses the format-v1 parameters: Argon2id, 3 passes, 64 MiB, 4 lanes, 32-byte output.
// The caller must obtain a 16-byte random salt once at registration and reuse it on all clients.
func Derive(password string, salt []byte) ([]byte, error) {
	if len(password) < 12 || len(password) > 1024 || len(salt) != 16 {
		return nil, errors.New("vault password must be 12–1024 bytes and salt must be 16 bytes")
	}
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32), nil
}
func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 requires a 32-byte key")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}

// Seal encrypts plaintext with a fresh nonce and binds it to the supplied account/record identity.
// Format is version byte 1, nonce, ciphertext, authentication tag.
func Seal(key, plaintext []byte, identity string) ([]byte, error) {
	g, e := aead(key)
	if e != nil {
		return nil, e
	}
	nonce := Random(g.NonceSize())
	out := append([]byte{1}, nonce...)
	return g.Seal(out, nonce, plaintext, []byte(identity)), nil
}

// Open authenticates and decrypts format-v1 data, returning an error for tampering or the wrong key.
func Open(key, data []byte, identity string) ([]byte, error) {
	g, e := aead(key)
	if e != nil {
		return nil, e
	}
	if len(data) < 1+g.NonceSize()+g.Overhead() || data[0] != 1 {
		return nil, errors.New("invalid encrypted record")
	}
	return g.Open(nil, data[1:1+g.NonceSize()], data[1+g.NonceSize():], []byte(identity))
}
