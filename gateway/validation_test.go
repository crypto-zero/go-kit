package gateway

import (
	"context"
	"errors"
	"testing"

	"buf.build/go/protovalidate"
	kiterrors "github.com/crypto-zero/go-kit/errors"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testValidator struct {
	err   error
	calls int
}

func (v *testValidator) Validate(proto.Message, ...protovalidate.ValidationOption) error {
	v.calls++
	return v.err
}

func TestValidateRequestAndCallValidatesBeforeNext(t *testing.T) {
	validationErr := errors.New("validation failed")
	validator := &testValidator{err: validationErr}
	var called bool

	got, err := ValidateRequestAndCall(validator, &emptypb.Empty{}, func() (string, error) {
		called = true
		return "ok", nil
	})
	if err == nil {
		t.Fatal("error = nil, want validation error")
	}
	if got != "" {
		t.Fatalf("result = %q, want zero value", got)
	}
	if called {
		t.Fatal("next was called, want validation to stop request")
	}
	if validator.calls != 1 {
		t.Fatalf("validator calls = %d, want 1", validator.calls)
	}
	if code := kiterrors.Code(err); code != 400 {
		t.Fatalf("error code = %d, want 400", code)
	}
	if reason := kiterrors.Reason(err); reason != defaultValidationReason {
		t.Fatalf("error reason = %q, want %q", reason, defaultValidationReason)
	}
}

func TestValidateRequestAndCallInvokesNextWhenValid(t *testing.T) {
	validator := &testValidator{}

	got, err := ValidateRequestAndCall(validator, &emptypb.Empty{}, func() (string, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("ValidateRequestAndCall: %v", err)
	}
	if got != "ok" {
		t.Fatalf("result = %q, want ok", got)
	}
	if validator.calls != 1 {
		t.Fatalf("validator calls = %d, want 1", validator.calls)
	}
}

func TestValidationUnaryInterceptorValidatesProtoRequest(t *testing.T) {
	validationErr := errors.New("validation failed")
	validator := &testValidator{err: validationErr}
	interceptor := ValidationUnaryInterceptor(validator)
	var called bool

	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		called = true
		return "ok", nil
	})
	if err == nil {
		t.Fatal("error = nil, want validation error")
	}
	if called {
		t.Fatal("handler was called, want validation to stop request")
	}
	if validator.calls != 1 {
		t.Fatalf("validator calls = %d, want 1", validator.calls)
	}
}

func TestValidationUnaryInterceptorSkipsNonProtoRequest(t *testing.T) {
	validator := &testValidator{err: errors.New("should not validate")}
	interceptor := ValidationUnaryInterceptor(validator)

	got, err := interceptor(context.Background(), "raw", &grpc.UnaryServerInfo{}, func(_ context.Context, req any) (any, error) {
		return req, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if got != "raw" {
		t.Fatalf("result = %v, want raw", got)
	}
	if validator.calls != 0 {
		t.Fatalf("validator calls = %d, want 0", validator.calls)
	}
}
