package grpcserver

import (
	"context"
	"log/slog"
	"testing"
	"time"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNewAppliesDefaults(t *testing.T) {
	srv := New(Config{}, grpc.NewServer())

	if srv.network != defaultNetwork {
		t.Fatalf("network = %q, want %q", srv.network, defaultNetwork)
	}
	if srv.addr != defaultAddr {
		t.Fatalf("addr = %q, want %q", srv.addr, defaultAddr)
	}
	if srv.Endpoint() != defaultAddr {
		t.Fatalf("Endpoint = %q, want %q", srv.Endpoint(), defaultAddr)
	}
	if srv.GRPCServer() == nil {
		t.Fatal("GRPCServer = nil, want server")
	}
}

func TestTrustedInt64MetadataInjectsContext(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-user-id", "42"))
	var gotID int64
	interceptor := TrustedInt64Metadata("x-user-id", func(ctx context.Context, id int64) context.Context {
		gotID = id
		return ctx
	})

	_, err := interceptor(ctx, &emptypb.Empty{}, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		return &emptypb.Empty{}, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if gotID != 42 {
		t.Fatalf("id = %d, want 42", gotID)
	}
}

func TestTrustedInt64MetadataRejectsInvalidMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-user-id", "bad"))
	interceptor := TrustedInt64Metadata("x-user-id", func(ctx context.Context, _ int64) context.Context {
		return ctx
	})

	_, err := interceptor(ctx, &emptypb.Empty{}, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		t.Fatal("handler was called, want metadata rejection")
		return nil, nil
	})
	if err == nil {
		t.Fatal("error = nil, want invalid metadata error")
	}
	if got := kiterrors.Code(err); got != 401 {
		t.Fatalf("error code = %d, want 401", got)
	}
}

func TestRecoveryConvertsPanic(t *testing.T) {
	interceptor := Recovery(slog.New(slog.DiscardHandler))

	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		panic("boom")
	})
	if err == nil {
		t.Fatal("error = nil, want recovered panic error")
	}
	if got := kiterrors.Code(err); got != 500 {
		t.Fatalf("error code = %d, want 500", got)
	}
}

func TestStopHonorsExpiredContext(t *testing.T) {
	srv := New(Config{}, grpc.NewServer())
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	if err := srv.Stop(ctx); err == nil {
		t.Fatal("Stop error = nil, want context deadline exceeded")
	}
}
