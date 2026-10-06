package ratelimit_test

import (
	"testing"
	"time"

	"github.com/scandeezy/std-login/internal/ratelimit"
	"github.com/scandeezy/std-login/internal/ratelimit/ratelimittest"
)

func TestMemoryConformance(t *testing.T) {
	ratelimittest.Run(t, func(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
		return ratelimit.NewMemory(limit, window)
	})
}
