package gateway

import (
	"buf.build/go/protovalidate"
	kiterrors "github.com/crypto-zero/go-kit/errors"
	"google.golang.org/protobuf/proto"
)

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
		return kiterrors.BadRequest("VALIDATION_FAILED", err.Error())
	}
	return nil
}
