// Package memory is an in-process store.Store, for tests and throwaway
// local runs. Data is lost on exit.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/scandeezy/std-login/internal/store"
)

type Store struct {
	mu            sync.Mutex
	users         map[string]store.User
	usersByEmail  map[string]string
	loginTokens   map[string]store.LoginToken
	sessions      map[string]store.Session
	refreshTokens map[string]store.RefreshToken
}

var _ store.Store = (*Store)(nil)

func New() *Store {
	return &Store{
		users:         map[string]store.User{},
		usersByEmail:  map[string]string{},
		loginTokens:   map[string]store.LoginToken{},
		sessions:      map[string]store.Session{},
		refreshTokens: map[string]store.RefreshToken{},
	}
}

func (s *Store) CreateUser(_ context.Context, u *store.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; ok {
		return store.ErrAlreadyExists
	}
	if _, ok := s.usersByEmail[u.Email]; ok {
		return store.ErrAlreadyExists
	}
	s.users[u.ID] = *u
	s.usersByEmail[u.Email] = u.ID
	return nil
}

func (s *Store) GetUser(_ context.Context, id string) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &u, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	s.mu.Lock()
	id, ok := s.usersByEmail[email]
	s.mu.Unlock()
	if !ok {
		return nil, store.ErrNotFound
	}
	return s.GetUser(ctx, id)
}

func (s *Store) UpdateUser(_ context.Context, u *store.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[u.ID]
	if !ok {
		return store.ErrNotFound
	}
	nu := *u
	nu.Email = old.Email
	s.users[u.ID] = nu
	return nil
}

func (s *Store) CreateLoginToken(_ context.Context, t *store.LoginToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.loginTokens[t.Hash]; ok {
		return store.ErrAlreadyExists
	}
	s.loginTokens[t.Hash] = *t
	return nil
}

func (s *Store) ConsumeLoginToken(_ context.Context, hash string) (*store.LoginToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.loginTokens[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	delete(s.loginTokens, hash)
	return &t, nil
}

func (s *Store) CreateSession(_ context.Context, sess *store.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sess.ID]; ok {
		return store.ErrAlreadyExists
	}
	s.sessions[sess.ID] = *sess
	return nil
}

func (s *Store) GetSession(_ context.Context, id string) (*store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &sess, nil
}

func (s *Store) RevokeSession(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return store.ErrNotFound
	}
	if sess.RevokedAt.IsZero() {
		sess.RevokedAt = at
		s.sessions[id] = sess
	}
	return nil
}

func (s *Store) CreateRefreshToken(_ context.Context, t *store.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refreshTokens[t.Hash]; ok {
		return store.ErrAlreadyExists
	}
	s.refreshTokens[t.Hash] = *t
	return nil
}

func (s *Store) UseRefreshToken(_ context.Context, hash string, at time.Time) (*store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refreshTokens[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !t.UsedAt.IsZero() {
		return &t, store.ErrAlreadyUsed
	}
	t.UsedAt = at
	s.refreshTokens[hash] = t
	return &t, nil
}

func (s *Store) PurgeExpired(_ context.Context, before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.loginTokens {
		if t.ExpiresAt.Before(before) {
			delete(s.loginTokens, k)
		}
	}
	for k, t := range s.refreshTokens {
		if t.ExpiresAt.Before(before) {
			delete(s.refreshTokens, k)
		}
	}
	return nil
}

func (s *Store) Close() error { return nil }
