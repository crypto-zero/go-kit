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
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

var errUnexpectedHandlerCall = errors.New("unexpected handler call")

func TestRecoveryConvertsPanic(t *testing.T) {
	interceptor := Recovery(slog.New(slog.DiscardHandler))
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
		`"stack":""`,
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

func TestLogPayloadRedactsSensitiveFields(t *testing.T) {
	payload, err := structpb.NewStruct(map[string]any{
		"signature":    "0xsecret",
		"access_token": "token",
		"nested": map[string]any{
			"upload_token": "upload-token",
			"safe":         "visible",
		},
	})
	if err != nil {
		t.Fatalf("new struct: %v", err)
	}
	raw, ok := logPayload(payload, newLoggingOptions().sensitiveFields).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(payload, newLoggingOptions().sensitiveFields))
	}
	body := string(raw)
	for _, secret := range []string{
		`"signature":"0xsecret"`,
		`"access_token":"token"`,
		`"upload_token":"upload-token"`,
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("payload leaked secret %q in %s", secret, body)
		}
	}
	if !strings.Contains(body, "visible") {
		t.Fatalf("payload removed safe field: %s", body)
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
