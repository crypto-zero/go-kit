package grpcx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	redactv1 "github.com/crypto-zero/go-kit/proto/kit/redact/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

var errUnexpectedHandlerCall = errors.New("unexpected handler call")

type generatedRedacter struct {
	*structpb.Struct
}

func (g *generatedRedacter) Redact() string {
	return `{"safe":"visible","secret":"[MASKED]"}`
}

type invalidGeneratedRedacter struct {
	*structpb.Struct
}

func (g *invalidGeneratedRedacter) Redact() string {
	return "masked"
}

func TestRecoveryConvertsPanic(t *testing.T) {
	var out bytes.Buffer
	interceptor := Recovery(slog.New(slog.NewJSONHandler(&out, nil)))
	req := &emptypb.Empty{}

	_, err := interceptor(context.Background(), req, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(_ context.Context, got any) (any, error) {
		if got != req {
			t.Fatalf("request = %v, want original request", got)
		}
		panic("boom")
	})
	if err == nil {
		t.Fatal("error = nil, want recovered panic error")
	}
	if got := kiterrors.Code(err); got != 500 {
		t.Fatalf("error code = %d, want 500", got)
	}
	body := out.String()
	for _, field := range []string{
		`"msg":"grpc panic recovered"`,
		`"method":"/test.Service/Method"`,
		`"panic":"boom"`,
		`"stack":"goroutine `,
		`grpcx.TestRecoveryConvertsPanic`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("panic log missing %s in %s", field, body)
		}
	}
}

func TestLoggingAddsKratosStyleFields(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	interceptor := Logging(logger)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "203.0.113.1",
		"user-agent", "test-client",
	))

	_, err := interceptor(ctx, &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		return &emptypb.Empty{}, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}

	body := out.String()
	for _, field := range []string{
		`"ip":"203.0.113.1"`,
		`"device":"test-client"`,
		`"kind":"server"`,
		`"component":"grpc"`,
		`"operation":"/test.Service/Method"`,
		`"args":{}`,
		`"reply":{}`,
		`"code":200`,
		`"reason":""`,
		`"latency":`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("log missing %s in %s", field, body)
		}
	}
}

func TestClientIPUsesForwardedMetadata(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "203.0.113.1, 10.0.0.1",
	))

	if got := ClientIP(ctx); got != "203.0.113.1" {
		t.Fatalf("ClientIP(ctx) = %q, want 203.0.113.1", got)
	}
}

func TestLogPayloadUsesGeneratedRedactMethod(t *testing.T) {
	payload, err := structpb.NewStruct(map[string]any{
		"safe":   "visible",
		"secret": "plain-secret",
	})
	if err != nil {
		t.Fatalf("new struct: %v", err)
	}
	raw, ok := logPayload(&generatedRedacter{Struct: payload}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(payload))
	}
	body := string(raw)
	for _, field := range []string{
		`"safe":"visible"`,
		`"secret":"[MASKED]"`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("payload missing generated redaction field %s in %s", field, body)
		}
	}
	if strings.Contains(body, "plain-secret") {
		t.Fatalf("payload leaked original secret in %s", body)
	}
}

func TestLogPayloadReturnsInvalidGeneratedRedactAsString(t *testing.T) {
	payload, err := structpb.NewStruct(map[string]any{
		"safe": "visible",
	})
	if err != nil {
		t.Fatalf("new struct: %v", err)
	}
	got := logPayload(&invalidGeneratedRedacter{Struct: payload})
	if got != "masked" {
		t.Fatalf("logPayload = %#v, want masked string", got)
	}
}

func TestLogPayloadUsesProtoNamesWithoutUnpopulatedFields(t *testing.T) {
	raw, ok := logPayload(&redactv1.RedactOptions{}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(&redactv1.RedactOptions{}))
	}
	body := string(raw)
	if body != "{}" {
		t.Fatalf("logPayload empty redact options = %s, want {}", body)
	}

	raw, ok = logPayload(&redactv1.RedactOptions{
		MaskValue: &redactv1.RedactOptions_StringMask{StringMask: "[MASKED]"},
	}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(&redactv1.RedactOptions{}))
	}
	body = string(raw)
	if !strings.Contains(body, `"string_mask":"[MASKED]"`) {
		t.Fatalf("logPayload redact options = %s, want proto field name string_mask", body)
	}
	if strings.Contains(body, "stringMask") || strings.Contains(body, `"redact":false`) {
		t.Fatalf("logPayload redact options = %s, want proto names without unpopulated fields", body)
	}
}

func TestLoggingWarnsForClientError(t *testing.T) {
	var out bytes.Buffer
	interceptor := Logging(slog.New(slog.NewJSONHandler(&out, nil)))
	errBadRequest := kiterrors.BadRequest("BAD_REQUEST", "bad request")

	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		return nil, errBadRequest
	})
	if !errors.Is(err, errBadRequest) {
		t.Fatalf("error = %v, want %v", err, errBadRequest)
	}
	body := out.String()
	for _, field := range []string{
		`"level":"WARN"`,
		`"msg":"grpc request failed"`,
		`"code":400`,
		`"reason":"BAD_REQUEST"`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("client error log missing %s in %s", field, body)
		}
	}
}

func TestLoggingErrorsForServerError(t *testing.T) {
	var out bytes.Buffer
	interceptor := Logging(slog.New(slog.NewJSONHandler(&out, nil)))
	errInternal := kiterrors.InternalServer("INTERNAL", "internal server error")

	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		return nil, errInternal
	})
	if !errors.Is(err, errInternal) {
		t.Fatalf("error = %v, want %v", err, errInternal)
	}
	body := out.String()
	for _, field := range []string{
		`"level":"ERROR"`,
		`"msg":"grpc request failed"`,
		`"code":500`,
		`"reason":"INTERNAL"`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("server error log missing %s in %s", field, body)
		}
	}
}

func TestLoggingReturnsHandlerError(t *testing.T) {
	interceptor := Logging(slog.New(slog.DiscardHandler))

	_, err := interceptor(context.Background(), &emptypb.Empty{}, nil, func(context.Context, any) (any, error) {
		return nil, errUnexpectedHandlerCall
	})
	if !errors.Is(err, errUnexpectedHandlerCall) {
		t.Fatalf("error = %v, want %v", err, errUnexpectedHandlerCall)
	}
}
