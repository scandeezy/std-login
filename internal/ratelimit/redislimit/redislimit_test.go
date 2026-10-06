package redislimit_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/scandeezy/std-login/internal/ratelimit"
	"github.com/scandeezy/std-login/internal/ratelimit/ratelimittest"
	"github.com/scandeezy/std-login/internal/ratelimit/redislimit"
)

func TestConformance(t *testing.T) {
	ratelimittest.Run(t, func(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
		mr := miniredis.RunT(t)
		return redislimit.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "test:", limit, window)
	})
}

// TestConformanceRealRedis runs the suite against a real server when
// REDIS_URL is set, e.g. REDIS_URL=redis://localhost:6379/15 go test ./...
func TestConformanceRealRedis(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(opts)
	t.Cleanup(func() { client.Close() })
	ratelimittest.Run(t, func(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
		// Unique prefix per subtest; keys expire on their own.
		return redislimit.New(client, "std-login-test:"+t.Name()+":"+time.Now().Format(time.RFC3339Nano)+":", limit, window)
	})
}

func TestKeysHashedAndExpire(t *testing.T) {
	mr := miniredis.RunT(t)
	l := redislimit.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "rl:", 5, time.Minute)
	if _, err := l.Allow(t.Context(), "email:alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}
	if strings.Contains(keys[0], "alice") || !strings.HasPrefix(keys[0], "rl:") {
		t.Errorf("key %q leaks input or lacks prefix", keys[0])
	}
	if ttl := mr.TTL(keys[0]); ttl <= 0 || ttl > time.Minute {
		t.Errorf("TTL = %v, want (0, 1m]", ttl)
	}
}

func TestRedisDown(t *testing.T) {
	mr := miniredis.RunT(t)
	l := redislimit.New(redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1}), "rl:", 5, time.Minute)
	mr.Close()
	if _, err := l.Allow(t.Context(), "k", time.Now()); err == nil {
		t.Fatal("expected error with Redis down")
	}
}
