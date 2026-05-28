package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingStore struct {
	key   string
	keys  []string
	n     int
	limit Limit
}

func (s *recordingStore) Take(_ context.Context, key string, _ time.Time, limit Limit, n int) (Result, error) {
	s.key = key
	s.n = n
	s.limit = limit
	return Result{Allowed: true, Remaining: limit.Burst - n}, nil
}

func (s *recordingStore) TakeMany(_ context.Context, keys []string, _ time.Time, limits []Limit, n int) ([]Result, error) {
	s.keys = append([]string(nil), keys...)
	s.n = n
	results := make([]Result, len(keys))
	for i, limit := range limits {
		results[i] = Result{Allowed: true, Remaining: limit.Burst - n}
	}
	return results, nil
}

func TestLimiterAllowsBurstThenRejects(t *testing.T) {
	now := time.Unix(0, 0)
	limiter, err := New(
		Config{Rate: 2, Per: time.Second, Burst: 2},
		WithStore(newInMemStore()),
		WithNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if res, err := limiter.AllowContext(context.Background(), "user-1"); err != nil || !res.Allowed || res.Remaining != 1 {
		t.Fatalf("first request = %+v, want allowed with one remaining", res)
	}
	if res, err := limiter.AllowContext(context.Background(), "user-1"); err != nil || !res.Allowed || res.Remaining != 0 {
		t.Fatalf("second request = %+v, want allowed with zero remaining", res)
	}
	if res, err := limiter.AllowContext(context.Background(), "user-1"); err != nil || res.Allowed || res.RetryAfter != 500*time.Millisecond {
		t.Fatalf("third request = %+v, want rejected with 500ms retry", res)
	}
}

func TestLimiterRefillsByElapsedTime(t *testing.T) {
	now := time.Unix(0, 0)
	limiter, err := New(
		Config{Rate: 2, Per: time.Second, Burst: 2},
		WithStore(newInMemStore()),
		WithNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := limiter.AllowContext(context.Background(), "user-1"); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := limiter.AllowContext(context.Background(), "user-1"); err != nil {
		t.Fatalf("second request: %v", err)
	}
	now = now.Add(500 * time.Millisecond)

	if res, err := limiter.AllowContext(context.Background(), "user-1"); err != nil || !res.Allowed || res.Remaining != 0 {
		t.Fatalf("refilled request = %+v, want allowed with zero remaining", res)
	}
}

func TestLimiterSeparatesKeys(t *testing.T) {
	limiter, err := New(Config{Rate: 1, Per: time.Second, Burst: 1}, WithStore(newInMemStore()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if res, err := limiter.AllowContext(context.Background(), "user-1"); err != nil || !res.Allowed {
		t.Fatalf("user-1 first request = %+v, want allowed", res)
	}
	if res, err := limiter.AllowContext(context.Background(), "user-1"); err != nil || res.Allowed {
		t.Fatalf("user-1 second request = %+v, want rejected", res)
	}
	if res, err := limiter.AllowContext(context.Background(), "user-2"); err != nil || !res.Allowed {
		t.Fatalf("user-2 first request = %+v, want allowed", res)
	}
}

func TestLimiterRejectsInvalidConfig(t *testing.T) {
	_, err := New(Config{Rate: 0, Per: time.Second, Burst: 1}, WithStore(newInMemStore()))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New error = %v, want ErrInvalidConfig", err)
	}

	_, err = New(Config{Rate: 1, Per: time.Nanosecond, Burst: 1}, WithStore(newInMemStore()))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New sub-ms config error = %v, want ErrInvalidConfig", err)
	}
}

func TestLimiterRejectsMissingStore(t *testing.T) {
	_, err := New(Config{Rate: 1, Per: time.Second, Burst: 1})
	if !errors.Is(err, ErrMissingStore) {
		t.Fatalf("New error = %v, want ErrMissingStore", err)
	}
}

func TestLimiterRejectsMissingKey(t *testing.T) {
	limiter, err := New(Config{Rate: 1, Per: time.Second, Burst: 1}, WithStore(newInMemStore()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = limiter.AllowContext(context.Background(), "")
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("AllowContext error = %v, want ErrMissingKey", err)
	}

	_, err = limiter.AllowNContext(context.Background(), "", 2)
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("AllowNContext over burst error = %v, want ErrMissingKey", err)
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
