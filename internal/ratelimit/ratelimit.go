// Package ratelimit provides fixed-window rate limiting keyed by arbitrary
// strings (client IP, email address).
//
// Memory is per process, so with several instances each one enforces its own
// limit and the effective limit multiplies by the instance count. Use
// redislimit for a limit shared across instances.
//
// Implementations must pass the conformance suite in ratelimit/ratelimittest.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

type Limiter interface {
	// Allow records an event for key and reports whether it is within
	// limit. An error means the limiter could not decide; callers choose
	// whether to fail open or closed.
	Allow(ctx context.Context, key string, now time.Time) (bool, error)
}

type window struct {
	start time.Time
	count int
}

// Memory allows Limit events per key per Window.
type Memory struct {
	Limit  int
	Window time.Duration

	mu      sync.Mutex
	windows map[string]*window
	swept   time.Time
}

func NewMemory(limit int, w time.Duration) *Memory {
	return &Memory{Limit: limit, Window: w, windows: map[string]*window{}}
}

func (m *Memory) Allow(_ context.Context, key string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Sub(m.swept) > m.Window {
		for k, w := range m.windows {
			if now.Sub(w.start) >= m.Window {
				delete(m.windows, k)
			}
		}
		m.swept = now
	}
	w, ok := m.windows[key]
	if !ok || now.Sub(w.start) >= m.Window {
		w = &window{start: now}
		m.windows[key] = w
	}
	w.count++
	return w.count <= m.Limit, nil
}

// Unlimited allows everything.
type Unlimited struct{}

func (Unlimited) Allow(context.Context, string, time.Time) (bool, error) { return true, nil }
