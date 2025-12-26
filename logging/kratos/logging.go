package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/http/status"
)

// Redacter defines how to log an object
type Redacter interface {
	Redact() string
}

// Server is an server logging middleware.
func Server(logger *slog.Logger) middleware.Middleware {
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
				"server request",
				"kind", "server",
				"component", kind,
				"operation", operation,
				"args", extractArgs(req),
				"reply", extractArgs(reply),
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
func Client(logger *slog.Logger) middleware.Middleware {
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
				"client request",
				"kind", "client",
				"component", kind,
				"operation", operation,
				"args", extractArgs(req),
				"reply", extractArgs(reply),
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
func extractArgs(args any) any {
	if redacter, ok := args.(Redacter); ok {
		// Return json.RawMessage so the logger won't escape the JSON string again
		return json.RawMessage(redacter.Redact())
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
