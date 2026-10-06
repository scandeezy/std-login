// Package ratelimittest is the conformance suite for ratelimit.Limiter
// implementations. Call Run from the implementation's own _test.go file.
package ratelimittest

import (
	"sync"
	"testing"
	"time"

	"github.com/scandeezy/std-login/internal/ratelimit"
)

// Factory returns a fresh limiter allowing limit events per window.
type Factory func(t *testing.T, limit int, window time.Duration) ratelimit.Limiter

// start is aligned to the window so implementations that use fixed,
// epoch-aligned buckets and ones that start a window at the first event
// behave identically.
var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func Run(t *testing.T, newLimiter Factory) {
	t.Run("Limit", func(t *testing.T) {
		l := newLimiter(t, 2, time.Minute)
		want := []bool{true, true, false, false}
		for i, w := range want {
			if got := allow(t, l, "a", start.Add(time.Duration(i)*time.Second)); got != w {
				t.Fatalf("event %d: allowed=%v, want %v", i+1, got, w)
			}
		}
	})

	t.Run("KeysIndependent", func(t *testing.T) {
		l := newLimiter(t, 1, time.Minute)
		if !allow(t, l, "a", start) || !allow(t, l, "b", start) {
			t.Fatal("first event for each key must be allowed")
		}
		if allow(t, l, "a", start) {
			t.Fatal("second event for a allowed")
		}
	})

	t.Run("WindowResets", func(t *testing.T) {
		l := newLimiter(t, 1, time.Minute)
		allow(t, l, "a", start)
		if allow(t, l, "a", start.Add(59*time.Second)) {
			t.Fatal("allowed within window")
		}
		if !allow(t, l, "a", start.Add(time.Minute)) {
			t.Fatal("not allowed after window")
		}
	})

	t.Run("Concurrent", func(t *testing.T) {
		l := newLimiter(t, 5, time.Minute)
		var wg sync.WaitGroup
		var mu sync.Mutex
		allowed := 0
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if allow(t, l, "a", start) {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if allowed != 5 {
			t.Fatalf("allowed %d concurrent events, want 5", allowed)
		}
	})
}

func allow(t *testing.T, l ratelimit.Limiter, key string, now time.Time) bool {
	t.Helper()
	ok, err := l.Allow(t.Context(), key, now)
	if err != nil {
		t.Errorf("Allow: %v", err)
	}
	return ok
}
