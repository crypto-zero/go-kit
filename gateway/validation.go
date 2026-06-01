package gateway

import (
	"context"

	"buf.build/go/protovalidate"
	kiterrors "github.com/crypto-zero/go-kit/errors"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const defaultValidationReason = "VALIDATION_FAILED"

// ValidateRequest validates a decoded proto request with protovalidate.
//
// grpc-gateway runtime middleware runs before generated handlers decode the
// request body into a proto message, so request validation must be called from a
// service wrapper or method entrypoint.
func ValidateRequest(validator protovalidate.Validator, req proto.Message) error {
	if validator == nil || req == nil {
		return nil
	}
	if err := validator.Validate(req); err != nil {
		return kiterrors.BadRequest(defaultValidationReason, err.Error())
	}
	return nil
}

// ValidateRequestAndCall validates req before calling next.
//
// It keeps handwritten service wrappers small when using grpc-gateway's
// in-process Register*HandlerServer path, where decoded proto messages only
// exist at the generated service method boundary.
func ValidateRequestAndCall[T any](
	validator protovalidate.Validator,
	req proto.Message,
	next func() (T, error),
) (T, error) {
	if err := ValidateRequest(validator, req); err != nil {
		var zero T
		return zero, err
	}
	return next()
}

// ValidationUnaryInterceptor returns a gRPC unary server interceptor that
// validates proto request messages before invoking the handler.
func ValidationUnaryInterceptor(validator protovalidate.Validator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		msg, ok := req.(proto.Message)
		if ok {
			if err := ValidateRequest(validator, msg); err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}
}
