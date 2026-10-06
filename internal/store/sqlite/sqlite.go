// Package sqlite is a store.Store backed by SQLite (pure Go driver, no cgo).
// Intended for local development and single-instance deployments.
//
// Times are stored as Unix milliseconds, with 0 meaning the zero time.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/scandeezy/std-login/internal/store"
)

//go:embed schema.sql
var schema string

type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// Open opens (creating if needed) the database at path and applies the
// schema. Use ":memory:" for an ephemeral database.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		// Each connection to :memory: is a separate database.
		db.SetMaxOpenConns(1)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func toMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMillis(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (s *Store) CreateUser(ctx context.Context, u *store.User) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, failed_logins, locked_until, session_generation, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.FailedLogins, toMillis(u.LockedUntil),
		u.SessionGeneration, toMillis(u.CreatedAt), toMillis(u.UpdatedAt))
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

const userColumns = `id, email, password_hash, failed_logins, locked_until, session_generation, created_at, updated_at`

func scanUser(row *sql.Row) (*store.User, error) {
	var u store.User
	var locked, created, updated int64
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FailedLogins, &locked, &u.SessionGeneration, &created, &updated); err != nil {
		return nil, notFound(err)
	}
	u.LockedUntil = fromMillis(locked)
	u.CreatedAt = fromMillis(created)
	u.UpdatedAt = fromMillis(updated)
	return &u, nil
}

func (s *Store) GetUser(ctx context.Context, id string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = ?`, email))
}

func (s *Store) UpdateUser(ctx context.Context, u *store.User) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, failed_logins = ?, locked_until = ?, session_generation = ?, updated_at = ?
		 WHERE id = ?`,
		u.PasswordHash, u.FailedLogins, toMillis(u.LockedUntil), u.SessionGeneration, toMillis(u.UpdatedAt), u.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) CreateLoginToken(ctx context.Context, t *store.LoginToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO login_tokens (hash, email, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		t.Hash, t.Email, toMillis(t.ExpiresAt), toMillis(t.CreatedAt))
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

func (s *Store) ConsumeLoginToken(ctx context.Context, hash string) (*store.LoginToken, error) {
	var t store.LoginToken
	var expires, created int64
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM login_tokens WHERE hash = ? RETURNING hash, email, expires_at, created_at`, hash).
		Scan(&t.Hash, &t.Email, &expires, &created)
	if err != nil {
		return nil, notFound(err)
	}
	t.ExpiresAt = fromMillis(expires)
	t.CreatedAt = fromMillis(created)
	return &t, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *store.Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, auth_time, auth_method, generation, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, toMillis(sess.AuthTime), sess.AuthMethod, sess.Generation, toMillis(sess.CreatedAt), toMillis(sess.RevokedAt))
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (*store.Session, error) {
	var sess store.Session
	var authTime, created, revoked int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, auth_time, auth_method, generation, created_at, revoked_at FROM sessions WHERE id = ?`, id).
		Scan(&sess.ID, &sess.UserID, &authTime, &sess.AuthMethod, &sess.Generation, &created, &revoked)
	if err != nil {
		return nil, notFound(err)
	}
	sess.AuthTime = fromMillis(authTime)
	sess.CreatedAt = fromMillis(created)
	sess.RevokedAt = fromMillis(revoked)
	return &sess, nil
}

func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = CASE WHEN revoked_at = 0 THEN ? ELSE revoked_at END WHERE id = ?`,
		toMillis(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) CreateRefreshToken(ctx context.Context, t *store.RefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (hash, session_id, user_id, expires_at, created_at, used_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.Hash, t.SessionID, t.UserID, toMillis(t.ExpiresAt), toMillis(t.CreatedAt), toMillis(t.UsedAt))
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

func (s *Store) UseRefreshToken(ctx context.Context, hash string, at time.Time) (*store.RefreshToken, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET used_at = ? WHERE hash = ? AND used_at = 0`, toMillis(at), hash)
	if err != nil {
		return nil, err
	}
	won, _ := res.RowsAffected()

	var t store.RefreshToken
	var expires, created, used int64
	err = s.db.QueryRowContext(ctx,
		`SELECT hash, session_id, user_id, expires_at, created_at, used_at FROM refresh_tokens WHERE hash = ?`, hash).
		Scan(&t.Hash, &t.SessionID, &t.UserID, &expires, &created, &used)
	if err != nil {
		return nil, notFound(err)
	}
	t.ExpiresAt = fromMillis(expires)
	t.CreatedAt = fromMillis(created)
	t.UsedAt = fromMillis(used)
	if won == 0 {
		return &t, store.ErrAlreadyUsed
	}
	return &t, nil
}

func (s *Store) PurgeExpired(ctx context.Context, before time.Time) error {
	ms := toMillis(before)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM login_tokens WHERE expires_at < ?`, ms); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < ?`, ms)
	return err
}
