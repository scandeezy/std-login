// Package redislimit is a ratelimit.Limiter backed by Redis, so limits are
// shared by every instance of the service.
//
// Windows are fixed and aligned to the Unix epoch: each (key, window) pair is
// one Redis counter, incremented and given a TTL of one window in a single
// MULTI. Keys are hashed so client IPs and email addresses are not stored in
// Redis in plain text.
package redislimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/scandeezy/std-login/internal/ratelimit"
)

type Limiter struct {
	client redis.UniversalClient
	prefix string
	limit  int
	window time.Duration
}

var _ ratelimit.Limiter = (*Limiter)(nil)

// New returns a limiter allowing limit events per window. prefix namespaces
// its keys; give each limiter sharing a Redis a distinct one.
func New(client redis.UniversalClient, prefix string, limit int, window time.Duration) *Limiter {
	return &Limiter{client: client, prefix: prefix, limit: limit, window: window}
}

func (l *Limiter) Allow(ctx context.Context, key string, now time.Time) (bool, error) {
	bucket := now.UnixMilli() / l.window.Milliseconds()
	sum := sha256.Sum256([]byte(key))
	k := l.prefix + hex.EncodeToString(sum[:16]) + ":" + strconv.FormatInt(bucket, 10)

	var incr *redis.IntCmd
	_, err := l.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		incr = p.Incr(ctx, k)
		p.PExpire(ctx, k, l.window)
		return nil
	})
	if err != nil {
		return false, err
	}
	return incr.Val() <= int64(l.limit), nil
}
