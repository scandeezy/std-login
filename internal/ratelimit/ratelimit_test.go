package ratelimit

import (
	"testing"
	"time"
)

func TestMemory(t *testing.T) {
	m := NewMemory(2, time.Minute)
	now := time.Now()
	if !m.Allow("a", now) || !m.Allow("a", now) {
		t.Fatal("within limit denied")
	}
	if m.Allow("a", now) {
		t.Fatal("over limit allowed")
	}
	if !m.Allow("b", now) {
		t.Fatal("keys not independent")
	}
	if !m.Allow("a", now.Add(time.Minute)) {
		t.Fatal("window did not reset")
	}
}
