package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingStore struct {
	key   string
	n     int
	limit Limit
}

func (s *recordingStore) Take(_ context.Context, key string, _ time.Time, limit Limit, n int) (Result, error) {
	s.key = key
	s.n = n
	s.limit = limit
	return Result{Allowed: true, Remaining: limit.Burst - n}, nil
}

func (s *recordingStore) Len(context.Context) (int, error) {
	return 0, nil
}

func TestLimiterAllowsBurstThenRejects(t *testing.T) {
	now := time.Unix(0, 0)
	limiter, err := New(Config{Rate: 2, Per: time.Second, Burst: 2}, WithNow(func() time.Time {
		return now
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if res := limiter.Allow("user-1"); !res.Allowed || res.Remaining != 1 {
		t.Fatalf("first request = %+v, want allowed with one remaining", res)
	}
	if res := limiter.Allow("user-1"); !res.Allowed || res.Remaining != 0 {
		t.Fatalf("second request = %+v, want allowed with zero remaining", res)
	}
	if res := limiter.Allow("user-1"); res.Allowed || res.RetryAfter != 500*time.Millisecond {
		t.Fatalf("third request = %+v, want rejected with 500ms retry", res)
	}
}

func TestLimiterRefillsByElapsedTime(t *testing.T) {
	now := time.Unix(0, 0)
	limiter, err := New(Config{Rate: 2, Per: time.Second, Burst: 2}, WithNow(func() time.Time {
		return now
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	limiter.Allow("user-1")
	limiter.Allow("user-1")
	now = now.Add(500 * time.Millisecond)

	if res := limiter.Allow("user-1"); !res.Allowed || res.Remaining != 0 {
		t.Fatalf("refilled request = %+v, want allowed with zero remaining", res)
	}
}

func TestLimiterSeparatesKeys(t *testing.T) {
	limiter, err := New(Config{Rate: 1, Per: time.Second, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if res := limiter.Allow("user-1"); !res.Allowed {
		t.Fatalf("user-1 first request = %+v, want allowed", res)
	}
	if res := limiter.Allow("user-1"); res.Allowed {
		t.Fatalf("user-1 second request = %+v, want rejected", res)
	}
	if res := limiter.Allow("user-2"); !res.Allowed {
		t.Fatalf("user-2 first request = %+v, want allowed", res)
	}
}

func TestLimiterEvictsOldestWhenMaxKeysReached(t *testing.T) {
	now := time.Unix(0, 0)
	limiter, err := New(Config{Rate: 1, Per: time.Second, Burst: 1, MaxKeys: 2}, WithNow(func() time.Time {
		return now
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	limiter.Allow("a")
	now = now.Add(time.Millisecond)
	limiter.Allow("b")
	now = now.Add(time.Millisecond)
	limiter.Allow("c")

	if got := limiter.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
	if res := limiter.Allow("a"); !res.Allowed {
		t.Fatalf("a should have been evicted and recreated with full burst, got %+v", res)
	}
}

func TestLimiterRejectsInvalidConfig(t *testing.T) {
	_, err := New(Config{Rate: 0, Per: time.Second, Burst: 1})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New error = %v, want ErrInvalidConfig", err)
	}
}

func TestLimiterUsesStore(t *testing.T) {
	store := &recordingStore{}
	limiter, err := New(Config{Rate: 5, Per: time.Second, Burst: 10}, WithStore(store))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := limiter.AllowNContext(context.Background(), "tenant-1", 3)
	if err != nil {
		t.Fatalf("AllowNContext: %v", err)
	}
	if !res.Allowed || res.Remaining != 7 {
		t.Fatalf("result = %+v, want allowed with 7 remaining", res)
	}
	if store.key != "tenant-1" || store.n != 3 {
		t.Fatalf("store saw key=%q n=%d, want tenant-1 and 3", store.key, store.n)
	}
	if store.limit.Rate != 5 || store.limit.Per != time.Second || store.limit.Burst != 10 {
		t.Fatalf("store limit = %+v, want configured limit", store.limit)
	}
}
