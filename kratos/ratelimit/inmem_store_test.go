package ratelimit

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// inMemStore is the token-bucket reference implementation shared by tests.
// It is the only Store fixture in the package; Take and TakeMany honor the
// atomicity guarantees in the Store interface doc.
type inMemStore struct {
	mu      sync.Mutex
	buckets map[string]*inMemBucket
}

type inMemBucket struct {
	tokens float64
	seen   time.Time
}

func newInMemStore() *inMemStore {
	return &inMemStore{buckets: make(map[string]*inMemBucket)}
}

func (s *inMemStore) Take(ctx context.Context, key string, now time.Time, limit Limit, n int) (Result, error) {
	results, err := s.TakeMany(ctx, []string{key}, now, []Limit{limit}, n)
	if err != nil {
		return Result{}, err
	}
	return results[0], nil
}

func (s *inMemStore) TakeMany(_ context.Context, keys []string, now time.Time, limits []Limit, n int) ([]Result, error) {
	if len(keys) != len(limits) {
		return nil, fmt.Errorf("keys/limits length mismatch")
	}
	if n <= 0 {
		results := make([]Result, len(keys))
		for i := range results {
			results[i] = Result{Allowed: true}
		}
		return results, nil
	}
	for i, key := range keys {
		if key == "" {
			return nil, ErrMissingKey
		}
		if err := limits[i].Validate(); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tokens := make([]float64, len(keys))
	buckets := make([]*inMemBucket, len(keys))
	for i, key := range keys {
		b := s.bucketFor(key, now, limits[i].Burst)
		refillInMemBucket(b, now, limits[i])
		buckets[i] = b
		tokens[i] = b.tokens
	}

	need := float64(n)
	allow := true
	for i := range buckets {
		if need > float64(limits[i].Burst) || tokens[i] < need {
			allow = false
			break
		}
	}

	results := make([]Result, len(keys))
	for i, b := range buckets {
		if allow {
			b.tokens -= need
			results[i] = Result{Allowed: true, Remaining: int(math.Floor(b.tokens))}
			continue
		}
		var retry time.Duration
		if need > float64(limits[i].Burst) {
			retry = retryAfter(limits[i], need-float64(limits[i].Burst))
		} else if tokens[i] < need {
			retry = retryAfter(limits[i], need-tokens[i])
		}
		results[i] = Result{
			Remaining:  int(math.Floor(tokens[i])),
			RetryAfter: retry,
		}
	}
	return results, nil
}

func (s *inMemStore) bucketFor(key string, now time.Time, burst int) *inMemBucket {
	if b, ok := s.buckets[key]; ok {
		return b
	}
	b := &inMemBucket{
		tokens: float64(burst),
		seen:   now,
	}
	s.buckets[key] = b
	return b
}

func refillInMemBucket(b *inMemBucket, now time.Time, limit Limit) {
	elapsed := now.Sub(b.seen)
	if elapsed <= 0 {
		return
	}
	per := time.Duration(inMemDurationMillis(limit.Per)) * time.Millisecond
	rate := float64(limit.Rate) / per.Seconds()
	b.tokens = math.Min(float64(limit.Burst), b.tokens+elapsed.Seconds()*rate)
	b.seen = now
}

func inMemDurationMillis(d time.Duration) int64 {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}
