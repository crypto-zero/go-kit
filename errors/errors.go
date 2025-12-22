package errors

import (
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	pberrors "github.com/crypto-zero/go-kit/proto/kit/errors/v1"
)

type PBError = pberrors.Error

type Error PBError

// Error return text message and http status code.
func (e *Error) Error() string {
	return fmt.Sprintf("error: code = %d reason = %s message = %s", e.Status, e.Info.Reason, e.Message)
}

// Is matches each error in the chain with the target value.
func (e *Error) Is(err error) bool {
	if se := new(Error); errors.As(err, &se) {
		return se.Status == e.Status && se.Info.Reason == e.Info.Reason
	}
	return false
}

// GRPCStatus returns the Status represented by se.
func (e *Error) GRPCStatus() *status.Status {
	s := &spb.Status{Code: int32(ToGRPCCode(int(e.Status))), Message: e.Message}
	if codes.Code(s.Code) == codes.OK {
		return status.FromProto(s)
	}
	s.Details = make([]*anypb.Any, 0, len(e.Details)+1)
	info, _ := anypb.New(e.Info)
	s.Details = append(s.Details, info)
	for _, detail := range e.Details {
		s.Details = append(s.Details, detail)
	}
	return status.FromProto(s)
}

// MarshalJSON marshals se to JSON.
func (e *Error) MarshalJSON() ([]byte, error) {
	pbErr := (*PBError)(e)
	return protojson.Marshal(pbErr)
}

// Clone returns a deep copy of se.
func (e *Error) Clone() *Error {
	if e == nil {
		return nil
	}
	newErr := proto.Clone((*PBError)(e))
	pbErr := newErr.(*PBError)
	return (*Error)(pbErr)
}

// SetMetadata set metadata for error info.
func (e *Error) SetMetadata(key, value string) *Error {
	copied := e.Clone()
	copied.Info.Metadata[key] = value
	return copied
}

// SetCause set cause for error info.
func (e *Error) SetCause(err error) *Error {
	if err == nil {
		return e
	}
	return e.SetMetadata("cause", err.Error())
}

// SetDomainAndCode set domain and code for info without clone.
func (e *Error) SetDomainAndCode(domain string, code int) *Error {
	if e.Info.Metadata == nil {
		e.Info.Metadata = make(map[string]string)
	}
	e.Info.Domain = domain
	e.Info.Metadata["code"] = fmt.Sprintf("%d", code)
	return e
}

const (
	// UnknownCode is unknown code for error info.
	UnknownCode = 500
	// UnknownReason is unknown reason for error info.
	UnknownReason = ""
)

// New returns an error object for the code, message.
func New(code int, reason, message string) *Error {
	return &Error{
		Status:  int32(code),
		Message: message,
		Info:    &errdetails.ErrorInfo{Reason: reason},
	}
}

// Newf New(code fmt.Sprintf(format, a...))
func Newf(code int, reason, format string, a ...any) *Error {
	return New(code, reason, fmt.Sprintf(format, a...))
}

// Errorf returns an error object for the code, message and error info.
func Errorf(code int, reason, format string, a ...any) error {
	return New(code, reason, fmt.Sprintf(format, a...))
}

// Code returns the http code for an error.
// It supports wrapped errors.
func Code(err error) int {
	if err == nil {
		return 200 //nolint:gomnd
	}
	return int(FromError(err).Status)
}

// Reason returns the reason for a particular error.
// It supports wrapped errors.
func Reason(err error) string {
	if err == nil {
		return UnknownReason
	}
	return FromError(err).Info.Reason
}

// FromError try to convert an error to *Error.
// It supports wrapped errors.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}
	if se := new(Error); errors.As(err, &se) {
		return se
	}
	gs, ok := status.FromError(err)
	if !ok {
		return New(UnknownCode, UnknownReason, err.Error())
	}
	ret := New(
		FromGRPCCode(gs.Code()),
		UnknownReason,
		gs.Message(),
	)
	ret.Details = make([]*anypb.Any, 0, len(gs.Details()))
	for _, detail := range gs.Proto().Details {
		ret.Details = append(ret.Details, detail)
	}
	if len(ret.Details) > 0 {
		first, err := ret.Details[0].UnmarshalNew()
		if err == nil {
			if info, ok := first.(*errdetails.ErrorInfo); ok {
				ret.Info.Reason, ret.Info.Domain = info.Reason, info.Domain
				ret.Info.Metadata = make(map[string]string, len(info.Metadata))
				for k, v := range info.Metadata {
					ret.Info.Metadata[k] = v
				}
				ret.Details = ret.Details[1:]
			}
		}
	}
	return ret
}

// BadRequest new BadRequest error that is mapped to a 400 response.
func BadRequest(reason, message string) *Error {
	return New(400, reason, message)
}

// IsBadRequest determines if err is an error which indicates a BadRequest error.
// It supports wrapped errors.
func IsBadRequest(err error) bool {
	return Code(err) == 400
}

// Unauthorized new Unauthorized error that is mapped to a 401 response.
func Unauthorized(reason, message string) *Error {
	return New(401, reason, message)
}

// IsUnauthorized determines if err is an error which indicates an Unauthorized error.
// It supports wrapped errors.
func IsUnauthorized(err error) bool {
	return Code(err) == 401
}

// Forbidden new Forbidden error that is mapped to a 403 response.
func Forbidden(reason, message string) *Error {
	return New(403, reason, message)
}

// IsForbidden determines if err is an error which indicates a Forbidden error.
// It supports wrapped errors.
func IsForbidden(err error) bool {
	return Code(err) == 403
}

// NotFound new NotFound error that is mapped to a 404 response.
func NotFound(reason, message string) *Error {
	return New(404, reason, message)
}

// IsNotFound determines if err is an error which indicates an NotFound error.
// It supports wrapped errors.
func IsNotFound(err error) bool {
	return Code(err) == 404
}

// Conflict new Conflict error that is mapped to a 409 response.
func Conflict(reason, message string) *Error {
	return New(409, reason, message)
}

// IsConflict determines if err is an error which indicates a Conflict error.
// It supports wrapped errors.
func IsConflict(err error) bool {
	return Code(err) == 409
}

// InternalServer new InternalServer error that is mapped to a 500 response.
func InternalServer(reason, message string) *Error {
	return New(500, reason, message)
}

// IsInternalServer determines if err is an error which indicates an Internal error.
// It supports wrapped errors.
func IsInternalServer(err error) bool {
	return Code(err) == 500
}

// ServiceUnavailable new ServiceUnavailable error that is mapped to an HTTP 503 response.
func ServiceUnavailable(reason, message string) *Error {
	return New(503, reason, message)
}

// IsServiceUnavailable determines if err is an error which indicates an Unavailable error.
// It supports wrapped errors.
func IsServiceUnavailable(err error) bool {
	return Code(err) == 503
}

// GatewayTimeout new GatewayTimeout error that is mapped to an HTTP 504 response.
func GatewayTimeout(reason, message string) *Error {
	return New(504, reason, message)
}

// IsGatewayTimeout determines if err is an error which indicates a GatewayTimeout error.
// It supports wrapped errors.
func IsGatewayTimeout(err error) bool {
	return Code(err) == 504
}

// ClientClosed new ClientClosed error that is mapped to an HTTP 499 response.
func ClientClosed(reason, message string) *Error {
	return New(499, reason, message)
}

// IsClientClosed determines if err is an error which indicates a IsClientClosed error.
// It supports wrapped errors.
func IsClientClosed(err error) bool {
	return Code(err) == 499
}
