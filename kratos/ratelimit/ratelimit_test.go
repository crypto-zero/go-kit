package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/metadata"
)

type mockTransport struct {
	operation string
}

func (m *mockTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (m *mockTransport) Endpoint() string                { return "localhost:8000" }
func (m *mockTransport) Operation() string               { return m.operation }
func (m *mockTransport) RequestHeader() transport.Header { return &mockHeader{} }
func (m *mockTransport) ReplyHeader() transport.Header   { return &mockHeader{} }

type mockHeader struct{}

func (m *mockHeader) Get(string) string      { return "" }
func (m *mockHeader) Set(string, string)     {}
func (m *mockHeader) Add(string, string)     {}
func (m *mockHeader) Keys() []string         { return nil }
func (m *mockHeader) Values(string) []string { return nil }

type errorStore struct {
	err error
}

func (s errorStore) Take(context.Context, string, time.Time, Limit, int) (Result, error) {
	return Result{}, s.err
}

func (s errorStore) TakeMany(context.Context, []string, time.Time, []Limit, int) ([]Result, error) {
	return nil, s.err
}

func mustServer(t *testing.T, opts ...Option) func(context.Context, any) (any, error) {
	t.Helper()
	mw, err := Server(opts...)
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	return mw(func(context.Context, any) (any, error) { return "ok", nil })
}

func TestServerRejectsWhenLimitExceeded(t *testing.T) {
	store := newInMemStore()
	wrapped := mustServer(t,
		WithRuleStore(store),
		WithOperationRules(OperationRules{
			"/svc/Test": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartClientIP},
			}},
		}),
		WithClientIPKeyFunc(ClientIPKey),
	)
	ctx := clientIPContext("/svc/Test", "192.168.1.10")

	if _, err := wrapped(ctx, nil); err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
	_, err := wrapped(ctx, nil)
	if !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("second request error = %v, want ErrLimitExceed", err)
	}
	se := kratoserrors.FromError(err)
	if se.Code != 429 || se.Reason != Reason || se.Metadata[MetadataRetryAfter] == "" {
		t.Fatalf("kratos error = %+v, want 429 RATELIMIT with retry_after", se)
	}
}

func TestServerRejectsMissingRules(t *testing.T) {
	if _, err := Server(); !errors.Is(err, ErrMissingRules) {
		t.Fatalf("Server error = %v, want ErrMissingRules", err)
	}
}

func TestServerRejectsMissingKey(t *testing.T) {
	wrapped := mustServer(t,
		WithRuleStore(newInMemStore()),
		WithOperationRules(OperationRules{
			"/svc/Test": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartClientIP},
			}},
		}),
		WithClientIPKeyFunc(ClientIPKey),
	)
	ctx := transport.NewServerContext(context.Background(), &mockTransport{operation: "/svc/Test"})

	_, err := wrapped(ctx, nil)
	if !errors.Is(err, ErrMissingKey) || !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("request error = %v, want ErrMissingKey cause on ErrLimitExceed", err)
	}
	se := kratoserrors.FromError(err)
	if se.Code != 429 || se.Reason != Reason {
		t.Fatalf("kratos error = %+v, want 429 RATELIMIT", se)
	}
}

func TestServerMapsStoreError(t *testing.T) {
	storeErr := errors.New("redis unavailable")
	wrapped := mustServer(t,
		WithRuleStore(errorStore{err: storeErr}),
		WithOperationRules(OperationRules{
			"/svc/Test": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartClientIP},
			}},
		}),
		WithClientIPKeyFunc(ClientIPKey),
	)
	ctx := clientIPContext("/svc/Test", "192.168.1.10")

	_, err := wrapped(ctx, nil)
	if !errors.Is(err, ErrStoreUnavailable) || !errors.Is(err, storeErr) {
		t.Fatalf("request error = %v, want ErrStoreUnavailable with store cause", err)
	}
	se := kratoserrors.FromError(err)
	if se.Code != 503 || se.Reason != "RATELIMIT_UNAVAILABLE" {
		t.Fatalf("kratos error = %+v, want 503 RATELIMIT_UNAVAILABLE", se)
	}
}

func TestServerMultiPartKeyMissingDimensionRejects(t *testing.T) {
	// With KeyParts=[user_id, client_ip], a missing user_id must not silently
	// degrade into a client_ip-only bucket — the composite key must be empty
	// and the request must be rejected with ErrMissingKey.
	wrapped := mustServer(t,
		WithRuleStore(newInMemStore()),
		WithOperationRules(OperationRules{
			"/svc/Test": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartUserID, KeyPartClientIP},
			}},
		}),
		WithClientIPKeyFunc(ClientIPKey),
		WithUserKeyFunc(func(context.Context, any) string { return "" }),
	)
	ctx := clientIPContext("/svc/Test", "192.168.1.10")

	if _, err := wrapped(ctx, nil); !errors.Is(err, ErrMissingKey) {
		t.Fatalf("request error = %v, want ErrMissingKey", err)
	}
}

func TestOperationPolicyEscapesKeyPartValues(t *testing.T) {
	store := newInMemStore()
	wrapped := mustServer(t,
		WithRuleStore(store),
		WithOperationRules(OperationRules{
			"/svc/Test": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartUserID},
			}},
		}),
		WithUserKeyFunc(func(context.Context, any) string { return "u%1:admin" }),
	)
	ctx := transport.NewServerContext(context.Background(), &mockTransport{operation: "/svc/Test"})

	if _, err := wrapped(ctx, nil); err != nil {
		t.Fatalf("request error = %v, want nil", err)
	}
	if _, ok := store.buckets["/svc/Test:user_id:u%251%3Aadmin"]; !ok {
		t.Fatalf("store buckets = %#v, want escaped key part value", store.buckets)
	}
}

func TestCompositeKey(t *testing.T) {
	key := CompositeKey(
		func(context.Context, any) string { return "/svc/A" },
		func(context.Context, any) string { return "127.0.0.1" },
	)(context.Background(), nil)

	if key != "/svc/A:127.0.0.1" {
		t.Fatalf("CompositeKey = %q, want joined key", key)
	}
}

func TestCompositeKeyReturnsEmptyWhenAnyPartIsEmpty(t *testing.T) {
	key := CompositeKey(
		func(context.Context, any) string { return "/svc/A" },
		func(context.Context, any) string { return "" },
	)(context.Background(), nil)

	if key != "" {
		t.Fatalf("CompositeKey = %q, want empty when any part is empty", key)
	}
}

func TestServerUsesOperationRules(t *testing.T) {
	store := newInMemStore()
	policy, err := NewOperationPolicy(
		store,
		OperationRules{
			"/test.limit.v1.LimitService/Fast": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartClientIP},
			}},
		},
		WithPolicyClientIPKeyFunc(ClientIPKey),
	)
	if err != nil {
		t.Fatalf("NewOperationPolicy: %v", err)
	}
	wrapped := mustServer(t, WithOperationPolicy(policy))
	fastCtx := clientIPContext("/test.limit.v1.LimitService/Fast", "192.168.1.10")
	slowCtx := transport.NewServerContext(context.Background(), &mockTransport{operation: "/test.limit.v1.LimitService/Slow"})

	if _, err := wrapped(fastCtx, nil); err != nil {
		t.Fatalf("fast first request error = %v, want nil", err)
	}
	if _, err := wrapped(fastCtx, nil); !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("fast second request error = %v, want ErrLimitExceed from operation policy", err)
	}
	for i := range 3 {
		if _, err := wrapped(slowCtx, nil); err != nil {
			t.Fatalf("slow request %d error = %v, want default limiter", i+1, err)
		}
	}
}

func TestOperationPolicyRejectsMissingKeyParts(t *testing.T) {
	_, err := NewOperationPolicy(
		newInMemStore(),
		OperationRules{
			"/test.limit.v1.LimitService/Fast": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: nil,
			}},
		},
	)
	if err == nil {
		t.Fatal("NewOperationPolicy error = nil, want error")
	}
}

func TestServerUsesOperationRulesOption(t *testing.T) {
	store := newInMemStore()
	wrapped := mustServer(t,
		WithRuleStore(store),
		WithOperationRules(OperationRules{
			"/test.limit.v1.LimitService/Fast": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartClientIP},
			}},
		}),
		WithClientIPKeyFunc(ClientIPKey),
	)
	ctx := clientIPContext("/test.limit.v1.LimitService/Fast", "192.168.1.10")

	if _, err := wrapped(ctx, nil); err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
	if _, err := wrapped(ctx, nil); !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("second request error = %v, want ErrLimitExceed from operation rule", err)
	}
}

func TestServerAppliesMultipleOperationRules(t *testing.T) {
	store := newInMemStore()
	wrapped := mustServer(t,
		WithRuleStore(store),
		WithOperationRules(OperationRules{
			"/test.limit.v1.LimitService/Fast": {
				{
					Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
					KeyParts: []KeyPart{KeyPartUserID},
				},
				{
					Config:   Config{Rate: 100, Per: time.Second, Burst: 100},
					KeyParts: []KeyPart{KeyPartClientIP},
				},
			},
		}),
		WithUserKeyFunc(func(context.Context, any) string { return "user-1" }),
		WithClientIPKeyFunc(ClientIPKey),
	)
	ctx := clientIPContext("/test.limit.v1.LimitService/Fast", "192.168.1.10")

	if _, err := wrapped(ctx, nil); err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
	if _, err := wrapped(ctx, nil); !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("second request error = %v, want ErrLimitExceed from user rule", err)
	}
}

// Multi-rule consumption must be atomic. Rule[0] is a tight per-user limit;
// rule[1] is a generous per-IP limit. Once the user rule starts rejecting,
// the IP rule must NOT have been silently decremented by the rejected
// attempts — otherwise a different user from the same IP would be wrongly
// throttled.
func TestServerMultiRuleConsumptionIsAtomic(t *testing.T) {
	store := newInMemStore()
	buildServer := func(userID string) func(context.Context, any) (any, error) {
		return mustServer(t,
			WithRuleStore(store),
			WithOperationRules(OperationRules{
				"/svc/Multi": {
					{
						Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
						KeyParts: []KeyPart{KeyPartUserID},
					},
					{
						Config:   Config{Rate: 100, Per: time.Second, Burst: 100},
						KeyParts: []KeyPart{KeyPartClientIP},
					},
				},
			}),
			WithUserKeyFunc(func(context.Context, any) string { return userID }),
			WithClientIPKeyFunc(ClientIPKey),
		)
	}

	user1 := buildServer("user-1")
	ctx := clientIPContext("/svc/Multi", "192.168.1.10")

	if _, err := user1(ctx, nil); err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
	for i := range 200 {
		if _, err := user1(ctx, nil); !errors.Is(err, ErrLimitExceed) {
			t.Fatalf("rejected request %d error = %v, want ErrLimitExceed", i+2, err)
		}
	}

	for i := range 99 {
		user := buildServer(fmt.Sprintf("user-%d", i+2))
		if _, err := user(ctx, nil); err != nil {
			t.Fatalf("user-2 request %d error = %v, want IP bucket still has 99 tokens", i+1, err)
		}
	}
}

func TestOperationPolicyRequiresUserKeyFunc(t *testing.T) {
	_, err := NewOperationPolicy(
		newInMemStore(),
		OperationRules{
			"/test.limit.v1.LimitService/Fast": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartUserID},
			}},
		},
	)
	if err == nil {
		t.Fatal("NewOperationPolicy error = nil, want missing user key func error")
	}
}

func TestOperationPolicyRequiresClientIPKeyFunc(t *testing.T) {
	_, err := NewOperationPolicy(
		newInMemStore(),
		OperationRules{
			"/test.limit.v1.LimitService/Fast": {{
				Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
				KeyParts: []KeyPart{KeyPartClientIP},
			}},
		},
	)
	if err == nil {
		t.Fatal("NewOperationPolicy error = nil, want missing client IP key func error")
	}
}

func TestOperationPolicyRequiresStore(t *testing.T) {
	_, err := NewOperationPolicy(nil, OperationRules{
		"/svc/A": {{Config: Config{Rate: 1, Per: time.Second, Burst: 1}, KeyParts: []KeyPart{KeyPartClientIP}}},
	})
	if !errors.Is(err, ErrMissingStore) {
		t.Fatalf("NewOperationPolicy error = %v, want ErrMissingStore", err)
	}
}

func TestOperationPolicyRejectsMissingRules(t *testing.T) {
	_, err := NewOperationPolicy(newInMemStore(), nil)
	if !errors.Is(err, ErrMissingRules) {
		t.Fatalf("NewOperationPolicy error = %v, want ErrMissingRules", err)
	}

	_, err = NewOperationPolicy(newInMemStore(), OperationRules{})
	if !errors.Is(err, ErrMissingRules) {
		t.Fatalf("NewOperationPolicy error = %v, want ErrMissingRules for empty rules", err)
	}
}

func TestServerRejectsConflictingOptions(t *testing.T) {
	policy, err := NewOperationPolicy(newInMemStore(), OperationRules{
		"/svc/A": {{Config: Config{Rate: 1, Per: time.Second, Burst: 1}, KeyParts: []KeyPart{KeyPartClientIP}}},
	}, WithPolicyClientIPKeyFunc(ClientIPKey))
	if err != nil {
		t.Fatalf("NewOperationPolicy: %v", err)
	}

	if _, err := Server(WithOperationPolicy(policy), WithClientIPKeyFunc(ClientIPKey)); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("Server error = %v, want ErrPolicyConflict when both policy and key func given", err)
	}
}

func TestServerRejectsInvalidOperationPolicy(t *testing.T) {
	if _, err := Server(WithOperationPolicy(&OperationPolicy{})); !errors.Is(err, ErrMissingRules) {
		t.Fatalf("Server error = %v, want ErrMissingRules for zero-value policy", err)
	}
}

func TestServerRejectsRuleBuildingOptionsWithoutRules(t *testing.T) {
	_, err := Server(WithRuleStore(newInMemStore()))
	if !errors.Is(err, ErrMissingRules) {
		t.Fatalf("Server error = %v, want ErrMissingRules", err)
	}

	_, err = Server(WithRuleStore(newInMemStore()), WithOperationRules(nil))
	if !errors.Is(err, ErrMissingRules) {
		t.Fatalf("Server error = %v, want ErrMissingRules for nil rules", err)
	}

	_, err = Server(WithRuleStore(newInMemStore()), WithOperationRules(OperationRules{}))
	if !errors.Is(err, ErrMissingRules) {
		t.Fatalf("Server error = %v, want ErrMissingRules for empty rules", err)
	}
}

func TestOperationPolicyScopesClientIPByOperation(t *testing.T) {
	store := newInMemStore()
	rules := OperationRules{
		"/svc/A": {{
			Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
			KeyParts: []KeyPart{KeyPartClientIP},
		}},
		"/svc/B": {{
			Config:   Config{Rate: 1, Per: time.Second, Burst: 1},
			KeyParts: []KeyPart{KeyPartClientIP},
		}},
	}
	policy, err := NewOperationPolicy(store, rules, WithPolicyClientIPKeyFunc(ClientIPKey))
	if err != nil {
		t.Fatalf("NewOperationPolicy: %v", err)
	}
	wrapped := mustServer(t, WithOperationPolicy(policy))
	ctxA := clientIPContext("/svc/A", "192.168.1.10")
	ctxB := clientIPContext("/svc/B", "192.168.1.10")

	if _, err := wrapped(ctxA, nil); err != nil {
		t.Fatalf("operation A first request error = %v, want nil", err)
	}
	if _, err := wrapped(ctxA, nil); !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("operation A second request error = %v, want ErrLimitExceed", err)
	}
	if _, err := wrapped(ctxB, nil); err != nil {
		t.Fatalf("operation B first request error = %v, want nil with operation-scoped client IP key", err)
	}
}

func clientIPContext(operation, ip string) context.Context {
	ctx := transport.NewServerContext(context.Background(), &mockTransport{operation: operation})
	return metadata.NewIncomingContext(ctx, metadata.Pairs("x-real-ip", ip))
}
