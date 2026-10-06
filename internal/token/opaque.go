package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewOpaque returns a 256-bit random URL-safe token (for login and refresh
// tokens) together with the hash under which it should be stored.
func NewOpaque() (tok, hash string) {
	b := make([]byte, 32)
	rand.Read(b) // never returns an error
	tok = base64.RawURLEncoding.EncodeToString(b)
	return tok, Hash(tok)
}

// Hash is the storage key for an opaque token. A plain SHA-256 is sufficient
// because the tokens are high-entropy random values, not user-chosen secrets.
func Hash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// NewID returns a random 128-bit identifier for users and sessions.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
