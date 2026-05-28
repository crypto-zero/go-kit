package ratelimit

import (
	"context"
	"errors"
	"math"
	"time"
)

var (
	// ErrInvalidConfig reports a limiter configuration that cannot be applied.
	ErrInvalidConfig = errors.New("invalid ratelimit config")
	// ErrMissingKey reports a request without a rate-limit key.
	ErrMissingKey = errors.New("missing ratelimit key")
	// ErrMissingStore reports a limiter constructed without a storage backend.
	ErrMissingStore = errors.New("missing ratelimit store")
)

// Config controls token-bucket behavior. It is also the limit type Store
// implementations consume; the Limit alias below preserves the name used on
// the Store interface.
type Config struct {
	// Rate is the number of tokens replenished every Per duration.
	Rate int
	// Per is the refill window for Rate tokens.
	Per time.Duration
	// Burst is the maximum number of tokens a key can accumulate.
	Burst int
}

// Validate reports whether c carries usable token-bucket parameters.
func (c Config) Validate() error {
	if c.Rate <= 0 || c.Per < time.Millisecond || c.Burst <= 0 {
		return ErrInvalidConfig
	}
	return nil
}

// Limit is the configuration carried into the Store. It is an alias of Config
// to keep the Store signature readable without introducing a second type.
type Limit = Config

// Result describes the outcome of an Allow call.
type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Store persists token-bucket state.
//
// Implementations must be safe for concurrent use. Take must apply atomically
// to one key. TakeMany must atomically check every key and either consume n
// tokens from all of them or from none of them, returning one Result per key
// in input order.
type Store interface {
	Take(ctx context.Context, key string, now time.Time, limit Limit, n int) (Result, error)
	TakeMany(ctx context.Context, keys []string, now time.Time, limits []Limit, n int) ([]Result, error)
}

// LimiterOption configures a Limiter.
type LimiterOption func(*Limiter)

// WithNow sets the clock used by the limiter.
func WithNow(now func() time.Time) LimiterOption {
	return func(l *Limiter) {
		if now != nil {
			l.now = now
		}
	}
}

// WithStore sets the storage backend used by the limiter.
func WithStore(store Store) LimiterOption {
	return func(l *Limiter) {
		if store != nil {
			l.store = store
		}
	}
}

// Limiter applies token-bucket rate limits independently per key.
type Limiter struct {
	limit Limit
	store Store
	now   func() time.Time
}

// New constructs a Limiter.
func New(cfg Config, opts ...LimiterOption) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	l := &Limiter{
		limit: cfg,
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	if l.store == nil {
		return nil, ErrMissingStore
	}
	return l, nil
}

// AllowContext consumes one token for key if capacity is available.
func (l *Limiter) AllowContext(ctx context.Context, key string) (Result, error) {
	return l.AllowNContext(ctx, key, 1)
}

// AllowNContext consumes n tokens for key if capacity is available.
func (l *Limiter) AllowNContext(ctx context.Context, key string, n int) (Result, error) {
	if n <= 0 {
		return Result{Allowed: true}, nil
	}
	if key == "" {
		return Result{}, ErrMissingKey
	}
	if n > l.limit.Burst {
		return Result{RetryAfter: retryAfter(l.limit, float64(n))}, nil
	}
	return l.store.Take(ctx, key, l.now(), l.limit, n)
}

func retryAfter(limit Limit, tokens float64) time.Duration {
	perToken := time.Duration(float64(limit.Per) / float64(limit.Rate))
	d := time.Duration(math.Ceil(float64(perToken) * tokens))
	if d < 0 {
		return 0
	}
	return d
}
