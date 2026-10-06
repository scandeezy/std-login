// Package ratelimit provides fixed-window rate limiting keyed by arbitrary
// strings (client IP, email address).
//
// Memory is per-process: when running several instances, replace it with a
// shared implementation of Limiter (e.g. Redis) or limits multiply by the
// instance count.
package ratelimit

import (
	"sync"
	"time"
)

type Limiter interface {
	// Allow records an event for key and reports whether it is within limit.
	Allow(key string, now time.Time) bool
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

func (m *Memory) Allow(key string, now time.Time) bool {
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
	return w.count <= m.Limit
}

// Unlimited allows everything.
type Unlimited struct{}

func (Unlimited) Allow(string, time.Time) bool { return true }
