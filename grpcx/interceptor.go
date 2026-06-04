// Package grpcx provides small gRPC server helpers.
package grpcx

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"time"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const okCode = 200

var defaultSensitiveFields = map[string]struct{}{
	"access_token":      {},
	"refresh_token":     {},
	"session_token":     {},
	"signature":         {},
	"token":             {},
	"upload_token":      {},
	"upload_token_hash": {},
}

// LoggingOption configures gRPC server request logging.
type LoggingOption func(*loggingOptions)

type loggingOptions struct {
	component       string
	deviceKeys      []string
	sensitiveFields map[string]struct{}
}

// WithLoggingComponent sets the logged component field.
func WithLoggingComponent(component string) LoggingOption {
	return func(o *loggingOptions) {
		o.component = component
	}
}

// WithDeviceMetadataKeys sets metadata keys used to fill the device field.
func WithDeviceMetadataKeys(keys ...string) LoggingOption {
	return func(o *loggingOptions) {
		o.deviceKeys = append([]string(nil), keys...)
	}
}

// WithSensitiveFields adds field names that should be redacted from logged payloads.
func WithSensitiveFields(fields ...string) LoggingOption {
	return func(o *loggingOptions) {
		if o.sensitiveFields == nil {
			o.sensitiveFields = make(map[string]struct{}, len(fields))
		}
		for _, field := range fields {
			o.sensitiveFields[strings.ToLower(field)] = struct{}{}
		}
	}
}

// Recovery returns a unary interceptor that converts panics into internal errors.
func Recovery(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(ctx, "grpc panic recovered", "method", fullMethod(info), "panic", recovered)
				err = kiterrors.InternalServer("INTERNAL", "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// Logging returns a unary interceptor with kratos-compatible request fields.
func Logging(logger *slog.Logger, opts ...LoggingOption) grpc.UnaryServerInterceptor {
	options := newLoggingOptions(opts...)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		latency := time.Since(start)
		method := fullMethod(info)
		code, reason, stack := errorFields(err)
		attrs := []any{
			"ip", ClientIP(ctx),
			"device", metadataValue(ctx, options.deviceKeys),
			"kind", "server",
			"component", options.component,
			"operation", method,
			"method", method,
			"args", logPayload(req, options.sensitiveFields),
			"reply", logPayload(resp, options.sensitiveFields),
			"code", code,
			"reason", reason,
			"stack", stack,
			"latency", latency.Seconds(),
			"duration", latency,
		}
		if err != nil {
			attrs = append(attrs, "err", err)
			logger.ErrorContext(ctx, "grpc request failed", attrs...)
			return resp, err
		}
		logger.InfoContext(ctx, "grpc request completed", attrs...)
		return resp, nil
	}
}

// ClientIP returns the most likely client IP from incoming gRPC context metadata.
func ClientIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, key := range []string{"x-forwarded-for", "x-real-ip", "cf-connecting-ip"} {
			values := md.Get(key)
			if len(values) == 0 {
				continue
			}
			if ip := firstIP(values[0]); ip != "" {
				return ip
			}
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return p.Addr.String()
		}
		return host
	}
	return ""
}

func newLoggingOptions(opts ...LoggingOption) loggingOptions {
	options := loggingOptions{
		component:       "grpc",
		deviceKeys:      []string{"user-agent", "grpc-user-agent", "x-device", "x-client-device"},
		sensitiveFields: make(map[string]struct{}, len(defaultSensitiveFields)),
	}
	for field := range defaultSensitiveFields {
		options.sensitiveFields[field] = struct{}{}
	}
	for _, opt := range opts {
		opt(&options)
	}
	return options
}

func fullMethod(info *grpc.UnaryServerInfo) string {
	if info == nil {
		return ""
	}
	return info.FullMethod
}

func errorFields(err error) (code int, reason, stack string) {
	if err == nil {
		return okCode, "", ""
	}
	return kiterrors.Code(err), kiterrors.Reason(err), err.Error()
}

func metadataValue(ctx context.Context, keys []string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range keys {
		values := md.Get(key)
		if len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func firstIP(value string) string {
	if before, _, ok := strings.Cut(value, ","); ok {
		value = before
	}
	return strings.TrimSpace(value)
}

func logPayload(v any, sensitiveFields map[string]struct{}) any {
	if v == nil {
		return json.RawMessage("{}")
	}
	pm, ok := v.(proto.Message)
	if !ok {
		return v
	}
	data, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(pm)
	if err != nil {
		return v
	}
	return redactJSON(data, sensitiveFields)
}

func redactJSON(data []byte, sensitiveFields map[string]struct{}) any {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return json.RawMessage(data)
	}
	redactValue(value, sensitiveFields)
	out, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(data)
	}
	return json.RawMessage(out)
}

func redactValue(value any, sensitiveFields map[string]struct{}) {
	switch v := value.(type) {
	case map[string]any:
		for key, field := range v {
			if _, ok := sensitiveFields[strings.ToLower(key)]; ok {
				v[key] = "[REDACTED]"
				continue
			}
			redactValue(field, sensitiveFields)
		}
	case []any:
		for _, item := range v {
			redactValue(item, sensitiveFields)
		}
	default:
	}
}
