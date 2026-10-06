// Package store defines the persistence facade for the login service.
//
// The interface is deliberately shaped for key/value or document databases:
// every operation addresses a single record by its primary key (or the user's
// normalized email, which is a unique secondary key), there are no joins, and
// the only atomicity required is a conditional single-record write
// (ConsumeLoginToken, UseRefreshToken). Bulk invalidation is expressed through
// a counter (User.SessionGeneration) rather than multi-record updates.
//
// Implementations must pass the shared conformance suite in store/storetest.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when the addressed record does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrAlreadyExists is returned by Create* when the key (or a user's
	// email) is already taken.
	ErrAlreadyExists = errors.New("store: already exists")
	// ErrAlreadyUsed is returned by UseRefreshToken when the token had
	// already been used. The record is still returned alongside it.
	ErrAlreadyUsed = errors.New("store: already used")
)

// User is an account. Email is stored normalized (see auth.NormalizeEmail) and
// is unique.
type User struct {
	ID    string
	Email string
	// PasswordHash is a PHC-format argon2id hash, or empty if no password
	// has been set.
	PasswordHash string
	// FailedLogins counts consecutive failed password attempts.
	FailedLogins int
	// LockedUntil disables password login until this time (zero = unlocked).
	LockedUntil time.Time
	// SessionGeneration is incremented to invalidate every existing
	// session; a session is live only while its Generation matches.
	SessionGeneration int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// LoginToken is an emailed one-time token. Only the SHA-256 hash of the token
// is stored.
type LoginToken struct {
	Hash      string
	Email     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Session groups the chain of refresh tokens issued from a single login.
type Session struct {
	ID     string
	UserID string
	// AuthTime is when the user actually authenticated; it is carried
	// unchanged across refreshes.
	AuthTime time.Time
	// AuthMethod is the JWT "amr" value for the login ("pwd" or "email").
	AuthMethod string
	// Generation is the user's SessionGeneration when the session started.
	Generation int64
	CreatedAt  time.Time
	RevokedAt  time.Time
}

// RefreshToken is one link in a session's rotation chain. Only the SHA-256
// hash of the token is stored.
type RefreshToken struct {
	Hash      string
	SessionID string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    time.Time
}

// Store is the persistence facade. All times are compared and stored with at
// least millisecond precision; implementations must return them in UTC.
type Store interface {
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// UpdateUser replaces the stored user record (matched by ID). Email is
	// immutable.
	UpdateUser(ctx context.Context, u *User) error

	CreateLoginToken(ctx context.Context, t *LoginToken) error
	// ConsumeLoginToken atomically deletes and returns the token, so it can
	// only be redeemed once. Expiry is checked by the caller.
	ConsumeLoginToken(ctx context.Context, hash string) (*LoginToken, error)

	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	// RevokeSession sets RevokedAt if it is not already set.
	RevokeSession(ctx context.Context, id string, at time.Time) error

	CreateRefreshToken(ctx context.Context, t *RefreshToken) error
	// UseRefreshToken atomically sets UsedAt if it is unset and returns the
	// token. If it was already set it returns the token and ErrAlreadyUsed.
	UseRefreshToken(ctx context.Context, hash string, at time.Time) (*RefreshToken, error)

	// PurgeExpired deletes login and refresh tokens that expired before the
	// given time. Stores with native TTL support may make this a no-op.
	PurgeExpired(ctx context.Context, before time.Time) error

	Close() error
}
