// Package password hashes and verifies passwords with argon2id, encoded in
// the PHC string format so parameters can be raised later without
// invalidating existing hashes (see NeedsRehash).
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinLength = 10  // characters
	MaxLength = 256 // bytes; bounds hashing cost of hostile input
)

var (
	ErrTooShort  = fmt.Errorf("password must be at least %d characters", MinLength)
	ErrTooLong   = fmt.Errorf("password must be at most %d bytes", MaxLength)
	ErrMalformed = errors.New("password: malformed hash")
)

// Params are argon2id cost parameters.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams follow the OWASP Password Storage Cheat Sheet minimum for
// argon2id (19 MiB, t=2, p=1).
var DefaultParams = Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// Hasher hashes and verifies passwords.
type Hasher struct {
	Params Params
	// dummy is a hash of a random password, verified against when the user
	// does not exist so both paths take the same time.
	dummy string
}

func NewHasher(p Params) *Hasher {
	h := &Hasher{Params: p}
	h.dummy, _ = h.Hash(rand.Text())
	return h
}

// Validate checks the password policy.
func Validate(pw string) error {
	if len(pw) > MaxLength {
		return ErrTooLong
	}
	if utf8.RuneCountInString(pw) < MinLength {
		return ErrTooShort
	}
	return nil
}

func (h *Hasher) Hash(pw string) (string, error) {
	salt := make([]byte, h.Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := h.Params
	key := argon2.IDKey([]byte(pw), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether pw matches the encoded hash. If encoded is empty
// (unknown user or no password set) it burns equivalent time against a dummy
// hash and returns false.
func (h *Hasher) Verify(pw, encoded string) bool {
	if encoded == "" || len(pw) > MaxLength {
		h.verify(pw, h.dummy)
		return false
	}
	ok, err := h.verify(pw, encoded)
	return err == nil && ok
}

// NeedsRehash reports whether encoded was produced with different parameters
// than the hasher's current ones.
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, _, _, err := decode(encoded)
	return err != nil || p.Memory != h.Params.Memory || p.Iterations != h.Params.Iterations ||
		p.Parallelism != h.Params.Parallelism || p.KeyLength != h.Params.KeyLength
}

func (h *Hasher) verify(pw, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	other := argon2.IDKey([]byte(pw), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return subtle.ConstantTimeCompare(key, other) == 1, nil
}

func decode(encoded string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, ErrMalformed
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrMalformed
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrMalformed
	}
	b64 := base64.RawStdEncoding
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return p, nil, nil, ErrMalformed
	}
	if key, err = b64.DecodeString(parts[5]); err != nil {
		return p, nil, nil, ErrMalformed
	}
	p.SaltLength, p.KeyLength = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}
