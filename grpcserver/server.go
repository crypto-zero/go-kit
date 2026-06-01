// Package grpcserver provides small helpers for internal gRPC servers.
package grpcserver

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	defaultNetwork = "tcp"
	defaultAddr    = "127.0.0.1:0"
)

// Config configures a gRPC server listener.
type Config struct {
	Network string
	Addr    string
}

// Server wraps a gRPC server with network-aware lifecycle methods.
type Server struct {
	server  *grpc.Server
	network string
	addr    string
}

// New constructs a gRPC server lifecycle wrapper.
func New(cfg Config, server *grpc.Server) *Server {
	network := cfg.Network
	if network == "" {
		network = defaultNetwork
	}
	addr := cfg.Addr
	if addr == "" {
		addr = defaultAddr
	}
	return &Server{server: server, network: network, addr: addr}
}

// Start listens and serves gRPC requests.
func (s *Server) Start() error {
	listener, err := net.Listen(s.network, s.addr)
	if err != nil {
		return err
	}
	return s.server.Serve(listener)
}

// Stop gracefully stops the gRPC server, forcing stop when ctx expires.
func (s *Server) Stop(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.server.Stop()
		return ctx.Err()
	}
}

// Endpoint returns the configured dial endpoint.
func (s *Server) Endpoint() string {
	return s.addr
}

// GRPCServer exposes the underlying gRPC server for tests and advanced registration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.server
}

// Recovery returns a unary interceptor that converts panics into internal errors.
func Recovery(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(ctx, "grpc panic recovered", slog.String("method", info.FullMethod), slog.Any("panic", recovered))
				err = kiterrors.InternalServer("INTERNAL", "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// Logging returns a unary interceptor with standard request logging.
func Logging(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		attrs := []any{
			slog.String("method", info.FullMethod),
			slog.Duration("duration", time.Since(start)),
		}
		if err != nil {
			attrs = append(attrs, slog.Any("err", err))
			logger.WarnContext(ctx, "grpc request failed", attrs...)
			return resp, err
		}
		logger.InfoContext(ctx, "grpc request completed", attrs...)
		return resp, nil
	}
}

// TrustedInt64Metadata returns a unary interceptor that trusts metadataKey as
// an internal int64 identity and injects it into the context.
func TrustedInt64Metadata(
	metadataKey string,
	inject func(context.Context, int64) context.Context,
) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			values := md.Get(metadataKey)
			if len(values) > 0 {
				id, err := strconv.ParseInt(values[0], 10, 64)
				if err != nil || id <= 0 {
					return nil, kiterrors.Unauthorized("INVALID_TOKEN", "invalid trusted metadata")
				}
				ctx = inject(ctx, id)
			}
		}
		return handler(ctx, req)
	}
}
