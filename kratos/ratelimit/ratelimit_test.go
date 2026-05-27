package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	ratelimitv1 "github.com/crypto-zero/go-kit/proto/kit/ratelimit/v1"
	"github.com/crypto-zero/go-kit/ratelimit"
	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/durationpb"
)

type mockTransport struct {
	operation string
}

func (m *mockTransport) Kind() transport.Kind { return transport.KindHTTP }
func (m *mockTransport) Endpoint() string     { return "localhost:8000" }
func (m *mockTransport) Operation() string    { return m.operation }
func (m *mockTransport) RequestHeader() transport.Header {
	return &mockHeader{}
}
func (m *mockTransport) ReplyHeader() transport.Header {
	return &mockHeader{}
}

type mockHeader struct{}

func (m *mockHeader) Get(string) string      { return "" }
func (m *mockHeader) Set(string, string)     {}
func (m *mockHeader) Add(string, string)     {}
func (m *mockHeader) Keys() []string         { return nil }
func (m *mockHeader) Values(string) []string { return nil }

func TestServerRejectsWhenLimitExceeded(t *testing.T) {
	limiter, err := ratelimit.New(ratelimit.Config{Rate: 1, Per: time.Second, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wrapped := Server(limiter)(func(context.Context, any) (any, error) {
		return "ok", nil
	})
	ctx := transport.NewServerContext(context.Background(), &mockTransport{operation: "/svc/Test"})

	if _, err := wrapped(ctx, nil); err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
	_, err = wrapped(ctx, nil)
	if err == nil {
		t.Fatal("second request error = nil, want rate-limit error")
	}
	if !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("second request error = %v, want ErrLimitExceed", err)
	}
	se := kratoserrors.FromError(err)
	if se.Code != 429 || se.Reason != reason || se.Metadata["retry_after"] == "" {
		t.Fatalf("kratos error = %+v, want 429 RATELIMIT with retry_after", se)
	}
}

func TestServerUsesOperationKeyByDefault(t *testing.T) {
	limiter, err := ratelimit.New(ratelimit.Config{Rate: 1, Per: time.Second, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wrapped := Server(limiter)(func(context.Context, any) (any, error) {
		return "ok", nil
	})

	ctxA := transport.NewServerContext(context.Background(), &mockTransport{operation: "/svc/A"})
	ctxB := transport.NewServerContext(context.Background(), &mockTransport{operation: "/svc/B"})
	if _, err := wrapped(ctxA, nil); err != nil {
		t.Fatalf("operation A error = %v, want nil", err)
	}
	if _, err := wrapped(ctxB, nil); err != nil {
		t.Fatalf("operation B error = %v, want nil because it has a separate bucket", err)
	}
}

func TestServerUsesCustomKeyFunc(t *testing.T) {
	limiter, err := ratelimit.New(ratelimit.Config{Rate: 1, Per: time.Second, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wrapped := Server(limiter, WithKeyFunc(func(context.Context, any) string {
		return "tenant-1"
	}))(func(context.Context, any) (any, error) {
		return "ok", nil
	})

	if _, err := wrapped(context.Background(), nil); err != nil {
		t.Fatalf("first request error = %v, want nil", err)
	}
	if _, err := wrapped(context.Background(), nil); !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("second request error = %v, want ErrLimitExceed", err)
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

func TestServerUsesProtoOperationPolicy(t *testing.T) {
	defaultLimiter, err := ratelimit.New(ratelimit.Config{Rate: 100, Per: time.Second, Burst: 100})
	if err != nil {
		t.Fatalf("New default limiter: %v", err)
	}
	policy := NewOperationPolicy(WithRateLimitFromProtoFiles(rateLimitFile(t)))
	wrapped := Server(defaultLimiter, WithOperationPolicy(policy))(func(context.Context, any) (any, error) {
		return "ok", nil
	})
	fastCtx := transport.NewServerContext(context.Background(), &mockTransport{operation: "/test.limit.v1.LimitService/Fast"})
	slowCtx := transport.NewServerContext(context.Background(), &mockTransport{operation: "/test.limit.v1.LimitService/Slow"})

	if _, err := wrapped(fastCtx, nil); err != nil {
		t.Fatalf("fast first request error = %v, want nil", err)
	}
	if _, err := wrapped(fastCtx, nil); !errors.Is(err, ErrLimitExceed) {
		t.Fatalf("fast second request error = %v, want ErrLimitExceed from proto policy", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := wrapped(slowCtx, nil); err != nil {
			t.Fatalf("slow request %d error = %v, want default limiter", i+1, err)
		}
	}
}

func rateLimitFile(t *testing.T) protoreflect.FileDescriptor {
	t.Helper()

	rateLimitOpts := &descriptorpb.MethodOptions{}
	proto.SetExtension(rateLimitOpts, ratelimitv1.E_RateLimit, &ratelimitv1.RateLimit{
		Rate:  1,
		Per:   durationpb.New(time.Second),
		Burst: 1,
		Key:   ratelimitv1.Key_KEY_OPERATION,
	})
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  proto.String("proto3"),
		Name:    proto.String("test/limit/v1/service.proto"),
		Package: proto.String("test.limit.v1"),
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("LimitService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       proto.String("Fast"),
					InputType:  proto.String(".test.limit.v1.FastRequest"),
					OutputType: proto.String(".test.limit.v1.FastResponse"),
					Options:    rateLimitOpts,
				},
				{
					Name:       proto.String("Slow"),
					InputType:  proto.String(".test.limit.v1.SlowRequest"),
					OutputType: proto.String(".test.limit.v1.SlowResponse"),
				},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("FastRequest")},
			{Name: proto.String("FastResponse")},
			{Name: proto.String("SlowRequest")},
			{Name: proto.String("SlowResponse")},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	return fd
}
