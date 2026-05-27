// Package ratelimit provides an in-memory token-bucket rate limiter.
package ratelimit

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

const defaultKey = "global"

var (
	// ErrInvalidConfig reports a limiter configuration that cannot be applied.
	ErrInvalidConfig = errors.New("invalid ratelimit config")

	// DefaultConfig is suitable for service-level protection.
	DefaultConfig = Config{
		Rate:    100,
		Per:     time.Minute,
		Burst:   100,
		MaxKeys: 10000,
	}
)

// Limit describes the token-bucket parameters used for one Allow call.
type Limit struct {
	// Rate is the number of tokens replenished every Per duration.
	Rate int
	// Per is the refill window for Rate tokens.
	Per time.Duration
	// Burst is the maximum number of tokens a key can accumulate.
	Burst int
}

// Config controls token-bucket behavior.
type Config struct {
	// Rate is the number of tokens replenished every Per duration.
	Rate int
	// Per is the refill window for Rate tokens.
	Per time.Duration
	// Burst is the maximum number of tokens a key can accumulate.
	Burst int
	// MaxKeys bounds the number of tracked buckets. Zero means unbounded.
	MaxKeys int
}

// Result describes the outcome of an Allow call.
type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Store persists token-bucket state.
//
// Implementations must apply the operation atomically for key. Distributed
// stores such as Redis should use ctx for cancellation and deadlines.
type Store interface {
	Take(ctx context.Context, key string, now time.Time, limit Limit, n int) (Result, error)
	Len(ctx context.Context) (int, error)
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithNow sets the clock used by the limiter.
func WithNow(now func() time.Time) Option {
	return func(l *Limiter) {
		if now != nil {
			l.now = now
		}
	}
}

// WithStore sets the storage backend used by the limiter.
func WithStore(store Store) Option {
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
func New(cfg Config, opts ...Option) (*Limiter, error) {
	if cfg.Rate <= 0 || cfg.Per <= 0 || cfg.Burst <= 0 || cfg.MaxKeys < 0 {
		return nil, ErrInvalidConfig
	}
	l := &Limiter{
		limit: Limit{
			Rate:  cfg.Rate,
			Per:   cfg.Per,
			Burst: cfg.Burst,
		},
		store: NewMemoryStore(cfg.MaxKeys),
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// NewDefault constructs a Limiter with DefaultConfig.
func NewDefault(opts ...Option) *Limiter {
	l, err := New(DefaultConfig, opts...)
	if err != nil {
		panic(err)
	}
	return l
}

// Allow consumes one token for key if capacity is available.
func (l *Limiter) Allow(key string) Result {
	return l.AllowN(key, 1)
}

// AllowContext consumes one token for key if capacity is available.
func (l *Limiter) AllowContext(ctx context.Context, key string) (Result, error) {
	return l.AllowNContext(ctx, key, 1)
}

// AllowN consumes n tokens for key if capacity is available.
func (l *Limiter) AllowN(key string, n int) Result {
	res, _ := l.AllowNContext(context.Background(), key, n)
	return res
}

// AllowNContext consumes n tokens for key if capacity is available.
func (l *Limiter) AllowNContext(ctx context.Context, key string, n int) (Result, error) {
	if n <= 0 {
		return Result{Allowed: true}, nil
	}
	if n > l.limit.Burst {
		return Result{RetryAfter: retryAfter(l.limit, float64(n))}, nil
	}
	if key == "" {
		key = defaultKey
	}
	return l.store.Take(ctx, key, l.now(), l.limit, n)
}

// Len returns the number of tracked buckets when the store supports counting.
func (l *Limiter) Len() int {
	n, _ := l.LenContext(context.Background())
	return n
}

// LenContext returns the number of tracked buckets when the store supports counting.
func (l *Limiter) LenContext(ctx context.Context) (int, error) {
	return l.store.Len(ctx)
}

// MemoryStore stores token buckets in memory.
type MemoryStore struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	maxKeys int
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// NewMemoryStore constructs an in-memory Store.
func NewMemoryStore(maxKeys int) *MemoryStore {
	return &MemoryStore{
		buckets: make(map[string]*bucket),
		maxKeys: maxKeys,
	}
}

// Take consumes n tokens from key if capacity is available.
func (s *MemoryStore) Take(_ context.Context, key string, now time.Time, limit Limit, n int) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := s.bucketFor(key, now, limit.Burst)
	refill(b, now, limit)
	need := float64(n)
	if b.tokens < need {
		return Result{
			Remaining:  int(math.Floor(b.tokens)),
			RetryAfter: retryAfter(limit, need-b.tokens),
		}, nil
	}
	b.tokens -= need
	return Result{
		Allowed:   true,
		Remaining: int(math.Floor(b.tokens)),
	}, nil
}

// Len returns the number of tracked buckets.
func (s *MemoryStore) Len(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets), nil
}

func (s *MemoryStore) bucketFor(key string, now time.Time, burst int) *bucket {
	if b, ok := s.buckets[key]; ok {
		return b
	}
	if s.maxKeys > 0 && len(s.buckets) >= s.maxKeys {
		s.evictOldest()
	}
	b := &bucket{
		tokens: float64(burst),
		seen:   now,
	}
	s.buckets[key] = b
	return b
}

func refill(b *bucket, now time.Time, limit Limit) {
	elapsed := now.Sub(b.seen)
	if elapsed <= 0 {
		b.seen = now
		return
	}
	rate := float64(limit.Rate) / limit.Per.Seconds()
	b.tokens = math.Min(float64(limit.Burst), b.tokens+elapsed.Seconds()*rate)
	b.seen = now
}

func retryAfter(limit Limit, tokens float64) time.Duration {
	perToken := time.Duration(float64(limit.Per) / float64(limit.Rate))
	d := time.Duration(math.Ceil(float64(perToken) * tokens))
	if d < 0 {
		return 0
	}
	return d
}

func (s *MemoryStore) evictOldest() {
	var (
		oldestKey string
		oldest    time.Time
	)
	for key, b := range s.buckets {
		if oldestKey == "" || b.seen.Before(oldest) {
			oldestKey = key
			oldest = b.seen
		}
	}
	delete(s.buckets, oldestKey)
}
