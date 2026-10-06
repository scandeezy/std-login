// Package storetest is the conformance suite every store.Store implementation
// must pass. Call Run from the implementation's own _test.go file.
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/scandeezy/std-login/internal/store"
)

// Factory returns a fresh, empty store. It is called once per subtest.
type Factory func(t *testing.T) store.Store

// now is millisecond-truncated UTC, the minimum precision stores must keep.
func now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

func Run(t *testing.T, newStore Factory) {
	tests := map[string]func(*testing.T, store.Store){
		"Users":         testUsers,
		"LoginTokens":   testLoginTokens,
		"Sessions":      testSessions,
		"RefreshTokens": testRefreshTokens,
		"PurgeExpired":  testPurgeExpired,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

func testUsers(t *testing.T, s store.Store) {
	ctx := context.Background()
	ts := now()
	u := &store.User{ID: "u1", Email: "a@example.com", CreatedAt: ts, UpdatedAt: ts}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.CreateUser(ctx, &store.User{ID: "u2", Email: "a@example.com", CreatedAt: ts, UpdatedAt: ts}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate email: got %v, want ErrAlreadyExists", err)
	}
	if err := s.CreateUser(ctx, &store.User{ID: "u1", Email: "b@example.com", CreatedAt: ts, UpdatedAt: ts}); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate id: got %v, want ErrAlreadyExists", err)
	}

	got, err := s.GetUserByEmail(ctx, "a@example.com")
	if err != nil || got.ID != "u1" {
		t.Fatalf("GetUserByEmail: %+v, %v", got, err)
	}
	if _, err := s.GetUser(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUser missing: %v", err)
	}
	if _, err := s.GetUserByEmail(ctx, "missing@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUserByEmail missing: %v", err)
	}

	got.PasswordHash = "hash"
	got.FailedLogins = 3
	got.LockedUntil = ts.Add(time.Minute)
	got.SessionGeneration = 7
	got.UpdatedAt = ts.Add(time.Second)
	if err := s.UpdateUser(ctx, got); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got2, err := s.GetUser(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if *got2 != *got {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", got2, got)
	}
	if err := s.UpdateUser(ctx, &store.User{ID: "missing"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateUser missing: %v", err)
	}
}

func testLoginTokens(t *testing.T, s store.Store) {
	ctx := context.Background()
	ts := now()
	tok := &store.LoginToken{Hash: "h1", Email: "a@example.com", ExpiresAt: ts.Add(time.Minute), CreatedAt: ts}
	if err := s.CreateLoginToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateLoginToken(ctx, tok); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}

	// Concurrent consumers: exactly one may win.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.ConsumeLoginToken(ctx, "h1")
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
				if *got != *tok {
					t.Errorf("consumed %+v, want %+v", got, tok)
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("ConsumeLoginToken: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("token consumed %d times, want 1", wins)
	}
}

func testSessions(t *testing.T, s store.Store) {
	ctx := context.Background()
	ts := now()
	sess := &store.Session{ID: "s1", UserID: "u1", AuthTime: ts, AuthMethod: "pwd", Generation: 2, CreatedAt: ts}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, sess); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	got, err := s.GetSession(ctx, "s1")
	if err != nil || *got != *sess {
		t.Fatalf("GetSession: %+v, %v", got, err)
	}
	if err := s.RevokeSession(ctx, "s1", ts.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Second revoke must not move the timestamp.
	if err := s.RevokeSession(ctx, "s1", ts.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSession(ctx, "s1")
	if !got.RevokedAt.Equal(ts.Add(time.Second)) {
		t.Fatalf("RevokedAt = %v, want %v", got.RevokedAt, ts.Add(time.Second))
	}
	if err := s.RevokeSession(ctx, "missing", ts); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeSession missing: %v", err)
	}
}

func testRefreshTokens(t *testing.T, s store.Store) {
	ctx := context.Background()
	ts := now()
	tok := &store.RefreshToken{Hash: "r1", SessionID: "s1", UserID: "u1", ExpiresAt: ts.Add(time.Hour), CreatedAt: ts}
	if err := s.CreateRefreshToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRefreshToken(ctx, tok); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.UseRefreshToken(ctx, "missing", ts); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UseRefreshToken missing: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, reused := 0, 0
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.UseRefreshToken(ctx, "r1", ts.Add(time.Second))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, store.ErrAlreadyUsed):
				reused++
			default:
				t.Errorf("UseRefreshToken: %v", err)
				return
			}
			if got == nil || got.SessionID != "s1" || !got.UsedAt.Equal(ts.Add(time.Second)) {
				t.Errorf("UseRefreshToken returned %+v", got)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || reused != 9 {
		t.Fatalf("wins=%d reused=%d, want 1 and 9", wins, reused)
	}
}

func testPurgeExpired(t *testing.T, s store.Store) {
	ctx := context.Background()
	ts := now()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.CreateLoginToken(ctx, &store.LoginToken{Hash: "old", Email: "a@example.com", ExpiresAt: ts.Add(-time.Minute), CreatedAt: ts}))
	must(s.CreateLoginToken(ctx, &store.LoginToken{Hash: "new", Email: "a@example.com", ExpiresAt: ts.Add(time.Minute), CreatedAt: ts}))
	must(s.CreateRefreshToken(ctx, &store.RefreshToken{Hash: "old", SessionID: "s", UserID: "u", ExpiresAt: ts.Add(-time.Minute), CreatedAt: ts}))
	must(s.CreateRefreshToken(ctx, &store.RefreshToken{Hash: "new", SessionID: "s", UserID: "u", ExpiresAt: ts.Add(time.Minute), CreatedAt: ts}))
	must(s.PurgeExpired(ctx, ts))

	if _, err := s.ConsumeLoginToken(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired login token not purged: %v", err)
	}
	if _, err := s.ConsumeLoginToken(ctx, "new"); err != nil {
		t.Errorf("live login token purged: %v", err)
	}
	if _, err := s.UseRefreshToken(ctx, "old", ts); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired refresh token not purged: %v", err)
	}
	if _, err := s.UseRefreshToken(ctx, "new", ts); err != nil {
		t.Errorf("live refresh token purged: %v", err)
	}
}
