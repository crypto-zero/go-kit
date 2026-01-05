package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/go-kratos/kratos/v2/transport/http/status"
)

// Redacter defines how to log an object
type Redacter interface {
	Redact() string
}

// Option is logging option.
type Option func(*options)

type options struct {
	skipRedact bool
}

// WithSkipRedact ignores the Redacter interface.
func WithSkipRedact() Option {
	return func(o *options) {
		o.skipRedact = true
	}
}

// Server is an server logging middleware.
func Server(logger *slog.Logger, opts ...Option) middleware.Middleware {
	options := &options{}
	for _, o := range opts {
		o(options)
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (reply any, err error) {
			var (
				code      int32
				reason    string
				kind      string
				operation string
			)

			// default code
			code = int32(status.FromGRPCCode(codes.OK))

			startTime := time.Now()
			if info, ok := transport.FromServerContext(ctx); ok {
				kind = info.Kind().String()
				operation = info.Operation()
			}
			reply, err = handler(ctx, req)
			if se := errors.FromError(err); se != nil {
				code = se.Code
				reason = se.Reason
			}
			level, stack := extractError(err)
			logger.Log(ctx, level,
				"server",
				"ip", GetClientIP(ctx),
				"device", GetClientDevice(ctx),
				"kind", "server",
				"component", kind,
				"operation", operation,
				"args", extractArgs(req, options.skipRedact),
				"reply", extractArgs(reply, options.skipRedact),
				"code", code,
				"reason", reason,
				"stack", stack,
				"latency", time.Since(startTime).Seconds(),
			)
			return
		}
	}
}

// Client is a client logging middleware.
func Client(logger *slog.Logger, opts ...Option) middleware.Middleware {
	options := &options{}
	for _, o := range opts {
		o(options)
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (reply any, err error) {
			var (
				code      int32
				reason    string
				kind      string
				operation string
			)

			// default code
			code = int32(status.FromGRPCCode(codes.OK))

			startTime := time.Now()
			if info, ok := transport.FromClientContext(ctx); ok {
				kind = info.Kind().String()
				operation = info.Operation()
			}
			reply, err = handler(ctx, req)
			if se := errors.FromError(err); se != nil {
				code = se.Code
				reason = se.Reason
			}
			level, stack := extractError(err)
			logger.Log(ctx, level,
				"client",
				"ip", GetClientIP(ctx),
				"device", GetClientDevice(ctx),
				"kind", "client",
				"component", kind,
				"operation", operation,
				"args", extractArgs(req, options.skipRedact),
				"reply", extractArgs(reply, options.skipRedact),
				"code", code,
				"reason", reason,
				"stack", stack,
				"latency", time.Since(startTime).Seconds(),
			)
			return
		}
	}
}

// extractArgs returns the args for logging.
// If req implements Redacter, returns json.RawMessage to avoid double JSON escaping.
// If req is a proto.Message, uses protojson to serialize it.
func extractArgs(args any, skipRedact bool) any {
	if !skipRedact {
		if redacter, ok := args.(Redacter); ok {
			// Return json.RawMessage so the logger won't escape the JSON string again
			return json.RawMessage(redacter.Redact())
		}
	}
	if pm, ok := args.(proto.Message); ok {
		// Use protojson for proto messages without Redacter
		return json.RawMessage(protojson.Format(pm))
	}
	if stringer, ok := args.(fmt.Stringer); ok {
		return stringer.String()
	}
	return fmt.Sprintf("%+v", args)
}

// extractError returns the slog level and error stack
func extractError(err error) (slog.Level, string) {
	if err != nil {
		return slog.LevelError, fmt.Sprintf("%+v", err)
	}
	return slog.LevelInfo, ""
}

// GetClientIP extracts the client IP address from the request context.
// Priority: X-Forwarded-For -> X-Real-IP -> RemoteAddr (HTTP) or Peer Address (gRPC).
// Supports both HTTP and gRPC transports.
// Returns normalized IP address (IPv4-mapped IPv6 converted to IPv4, Zone ID removed).
func GetClientIP(ctx context.Context) string {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return ""
	}

	// Handle HTTP transport
	if httpTr, ok := tr.(*kratoshttp.Transport); ok {
		return getClientIPFromHTTP(httpTr)
	}

	// Handle gRPC transport
	return getClientIPFromGRPC(ctx)
}

// getClientIPFromHTTP extracts client IP from HTTP request.
func getClientIPFromHTTP(httpTr *kratoshttp.Transport) string {
	req := httpTr.Request()
	if req == nil {
		return ""
	}

	if ip := extractIP(req.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}

	if ip := extractIP(req.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return normalizeIP(req.RemoteAddr)
	}
	return normalizeIP(host)
}

// getClientIPFromGRPC extracts client IP from gRPC context.
func getClientIPFromGRPC(ctx context.Context) string {
	// Try to get forwarded headers from gRPC metadata first
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		// Check X-Forwarded-For
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			if ip := extractIP(xff[0]); ip != "" {
				return ip
			}
		}
		// Check X-Real-IP
		if xrip := md.Get("x-real-ip"); len(xrip) > 0 {
			if ip := extractIP(xrip[0]); ip != "" {
				return ip
			}
		}
	}

	// Fall back to peer address
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return normalizeIP(p.Addr.String())
		}
		return normalizeIP(host)
	}

	return ""
}

// extractIP extracts the first valid IP from a header value (e.g., X-Forwarded-For).
// It handles comma-separated values (taking the first one) and applies normalization.
func extractIP(headerVal string) string {
	if headerVal == "" {
		return ""
	}
	// X-Forwarded-For can contain multiple IPs, the first one is the client IP.
	// Use IndexByte instead of Split to avoid memory allocation.
	if idx := strings.IndexByte(headerVal, ','); idx != -1 {
		headerVal = headerVal[:idx]
	}
	return normalizeIP(strings.TrimSpace(headerVal))
}

// normalizeIP validates and normalizes an IP address string.
// It performs the following normalizations:
//   - Removes IPv6 zone ID (e.g., "fe80::1%eth0" -> "fe80::1")
//   - Converts IPv4-mapped IPv6 to IPv4 (e.g., "::ffff:192.168.1.1" -> "192.168.1.1")
//
// Returns empty string if the input is not a valid IP address.
func normalizeIP(ip string) string {
	if ip == "" {
		return ""
	}

	// Remove IPv6 zone ID (e.g., fe80::1%eth0 -> fe80::1)
	if idx := strings.IndexByte(ip, '%'); idx != -1 {
		ip = ip[:idx]
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	// Convert IPv4-mapped IPv6 to IPv4 (e.g., ::ffff:192.168.1.1 -> 192.168.1.1)
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4.String()
	}

	return parsed.String()
}

// GetClientDevice extracts the client device info (User-Agent) from the request context.
// Supports both HTTP and gRPC transports.
func GetClientDevice(ctx context.Context) string {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return ""
	}

	// Handle HTTP transport
	if httpTr, ok := tr.(*kratoshttp.Transport); ok {
		return httpTr.Request().UserAgent()
	}

	// Handle gRPC transport
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		// gRPC usually passes user-agent in metadata
		if ua := md.Get("user-agent"); len(ua) > 0 {
			return ua[0]
		}
		if ua := md.Get("grpc-user-agent"); len(ua) > 0 {
			return ua[0]
		}
	}

	return ""
}
