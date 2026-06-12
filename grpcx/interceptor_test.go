package grpcx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	redactv1 "github.com/crypto-zero/go-kit/proto/kit/redact/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	if strings.Contains(body, `"method":`) {
		t.Fatalf("request log contains duplicate method field (operation already carries it): %s", body)
	}
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

func TestLoggingSkipsGeneratedRedaction(t *testing.T) {
	var out bytes.Buffer
	interceptor := Logging(slog.New(slog.NewJSONHandler(&out, nil)), WithSkipRedact())
	payload, err := structpb.NewStruct(map[string]any{
		"safe":   "visible",
		"secret": "plain-secret",
	})
	if err != nil {
		t.Fatalf("new struct: %v", err)
	}

	_, err = interceptor(context.Background(), &generatedRedacter{Struct: payload}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `plain-secret`) {
		t.Fatalf("log = %s, want original payload when redaction is skipped", body)
	}
	if strings.Contains(body, `[MASKED]`) {
		t.Fatalf("log used generated redaction despite WithSkipRedact: %s", body)
	}
}

func TestClientIPUsesRightmostValidForwardedFor(t *testing.T) {
	// The leftmost x-forwarded-for entries are client-controlled (proxies
	// append, clients can pre-fill); the rightmost valid IP is the closest
	// verifiable hop.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "203.0.113.1, 10.0.0.1",
	))

	if got := ClientIP(ctx); got != "10.0.0.1" {
		t.Fatalf("ClientIP(ctx) = %q, want 10.0.0.1", got)
	}
}

func TestClientIPPrefersOverwriteStyleHeaders(t *testing.T) {
	// cf-connecting-ip / x-real-ip are single-value headers overwritten by a
	// trusted edge; they beat the append-style x-forwarded-for.
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "203.0.113.9, 10.0.0.1",
		"cf-connecting-ip", "198.51.100.7",
	))

	if got := ClientIP(ctx); got != "198.51.100.7" {
		t.Fatalf("ClientIP(ctx) = %q, want 198.51.100.7", got)
	}
}

func TestClientIPSkipsInvalidForwardedValues(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "<script>alert(1)</script>, also-not-an-ip",
		"x-real-ip", "not-an-ip",
	))

	if got := ClientIP(ctx); got != "" {
		t.Fatalf("ClientIP(ctx) = %q, want empty for garbage headers without peer", got)
	}
}

func TestClientIPParsesIPv6(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "2001:db8::1",
	))

	if got := ClientIP(ctx); got != "2001:db8::1" {
		t.Fatalf("ClientIP(ctx) = %q, want 2001:db8::1", got)
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
	raw, ok := logPayload(&generatedRedacter{Struct: payload}, loggingOptions{}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(payload, loggingOptions{}))
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

func TestLogPayloadSkipsGeneratedRedactMethod(t *testing.T) {
	payload, err := structpb.NewStruct(map[string]any{
		"safe":   "visible",
		"secret": "plain-secret",
	})
	if err != nil {
		t.Fatalf("new struct: %v", err)
	}
	raw, ok := logPayload(&generatedRedacter{Struct: payload}, loggingOptions{skipRedact: true}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(payload, loggingOptions{}))
	}
	body := string(raw)
	if !strings.Contains(body, `"secret":"plain-secret"`) {
		t.Fatalf("payload = %s, want original secret when redaction is skipped", body)
	}
	if strings.Contains(body, "[MASKED]") {
		t.Fatalf("payload used generated redaction despite skipRedact: %s", body)
	}
}

func TestLogPayloadReturnsInvalidGeneratedRedactAsString(t *testing.T) {
	payload, err := structpb.NewStruct(map[string]any{
		"safe": "visible",
	})
	if err != nil {
		t.Fatalf("new struct: %v", err)
	}
	got := logPayload(&invalidGeneratedRedacter{Struct: payload}, loggingOptions{})
	if got != "masked" {
		t.Fatalf("logPayload = %#v, want masked string", got)
	}
}

func TestLogPayloadUsesProtoNamesWithoutUnpopulatedFields(t *testing.T) {
	raw, ok := logPayload(&redactv1.RedactOptions{}, loggingOptions{}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(&redactv1.RedactOptions{}, loggingOptions{}))
	}
	body := string(raw)
	if body != "{}" {
		t.Fatalf("logPayload empty redact options = %s, want {}", body)
	}

	raw, ok = logPayload(&redactv1.RedactOptions{
		MaskValue: &redactv1.RedactOptions_StringMask{StringMask: "[MASKED]"},
	}, loggingOptions{}).(json.RawMessage)
	if !ok {
		t.Fatalf("log payload type = %T, want json.RawMessage", logPayload(&redactv1.RedactOptions{}, loggingOptions{}))
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

func TestLoggingWarnsForClientCancellation(t *testing.T) {
	var out bytes.Buffer
	interceptor := Logging(slog.New(slog.NewJSONHandler(&out, nil)))
	cancelErr := fmt.Errorf("stream points: %w", context.Canceled)

	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		return nil, cancelErr
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want wrapped context.Canceled", err)
	}
	body := out.String()
	for _, field := range []string{
		`"level":"WARN"`,
		`"code":499`,
		`"reason":"CANCELLED"`,
	} {
		if !strings.Contains(body, field) {
			t.Fatalf("client cancellation log missing %s in %s", field, body)
		}
	}
}

func TestErrorFieldsMapsContextTermination(t *testing.T) {
	sentinel := kiterrors.ServiceUnavailable("UPSTREAM_CHECK_FAILED", "upstream check failed")
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantReason string
	}{
		{"canceled", fmt.Errorf("x: %w", context.Canceled), 499, "CANCELLED"},
		{"deadline exceeded", fmt.Errorf("x: %w", context.DeadlineExceeded), 504, "DEADLINE_EXCEEDED"},
		{
			"deliberate error wrapping timeout keeps its own code",
			fmt.Errorf("%w: %w", sentinel, context.DeadlineExceeded),
			503, "UPSTREAM_CHECK_FAILED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, reason := errorFields(tc.err)
			if code != tc.wantCode || reason != tc.wantReason {
				t.Fatalf("errorFields(%v) = (%d, %q), want (%d, %q)",
					tc.err, code, reason, tc.wantCode, tc.wantReason)
			}
		})
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

var errNotFoundSentinel = kiterrors.NotFound("RESOURCE_NOT_FOUND", "resource not found")

func TestNormalizeErrorPassesDeliberateErrorsThrough(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"kit error", errNotFoundSentinel},
		{"wrapped kit error", fmt.Errorf("get resource: %w", errNotFoundSentinel)},
		{"grpc status error", status.Error(codes.NotFound, "no such method")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeError(tc.err); !errors.Is(got, tc.err) {
				t.Fatalf("normalizeError(%v) = %v, want the original error preserved", tc.err, got)
			}
		})
	}
}

func TestNormalizeErrorRedactsUnknownErrors(t *testing.T) {
	const internalDetail = "dial tcp 10.0.0.1:5432: connection refused"
	cases := []struct {
		name string
		err  error
	}{
		{"plain error", errors.New(internalDetail)},
		{"wrapped plain error", fmt.Errorf("query backend: %w", errors.New(internalDetail))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeError(tc.err)
			st, _ := status.FromError(got)
			if st.Code() != codes.Internal {
				t.Fatalf("normalizeError(%v) code = %v, want %v", tc.err, st.Code(), codes.Internal)
			}
			if strings.Contains(st.Message(), "10.0.0.1") {
				t.Fatalf("normalizeError leaked internal detail to client: %q", st.Message())
			}
			e := kiterrors.FromError(got)
			if e.Info == nil || e.Info.Reason == kiterrors.UnknownReason {
				t.Fatalf("normalized error has no deliberate reason: %+v", e)
			}
		})
	}
}

// TestNormalizeErrorPrefersDeliberateErrorOverWrappedContextError pins the
// precedence: when a deliberate kit error wraps a context timeout from an
// internal sub-call (RPC client timeout etc.), the deliberate error must
// reach the client — the inbound request itself did not time out.
func TestNormalizeErrorPrefersDeliberateErrorOverWrappedContextError(t *testing.T) {
	sentinel := kiterrors.ServiceUnavailable("UPSTREAM_CHECK_FAILED", "upstream check failed")
	err := fmt.Errorf("%w: %w", sentinel, context.DeadlineExceeded)

	got := normalizeError(err)
	if !errors.Is(got, sentinel) {
		t.Fatalf("normalizeError(%v) = %v, want the deliberate sentinel preserved", err, got)
	}
	st, _ := status.FromError(got)
	if st.Code() == codes.DeadlineExceeded {
		t.Fatalf("normalizeError(%v) code = %v; wrapped sub-call timeout must not mask the deliberate error", err, st.Code())
	}
}

func TestNormalizeErrorKeepsContextCodes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"canceled", fmt.Errorf("await session: %w", context.Canceled), codes.Canceled},
		{"deadline exceeded", fmt.Errorf("query: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := status.FromError(normalizeError(tc.err))
			if st.Code() != tc.want {
				t.Fatalf("normalizeError(%v) code = %v, want %v", tc.err, st.Code(), tc.want)
			}
		})
	}
}

func TestErrorNormalizationSanitizesHandlerErrors(t *testing.T) {
	interceptor := ErrorNormalization()
	handler := func(context.Context, any) (any, error) {
		cause := errors.New(`pq: password authentication failed for user "postgres"`)
		return nil, fmt.Errorf("query resources: %w", cause)
	}
	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, handler)
	if err == nil {
		t.Fatal("interceptor returned nil error, want sanitized internal error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Fatalf("code = %v, want %v", st.Code(), codes.Internal)
	}
	if strings.Contains(st.Message(), "postgres") {
		t.Fatalf("interceptor leaked internal detail: %q", st.Message())
	}
}

func TestErrorNormalizationPassesResponsesThrough(t *testing.T) {
	interceptor := ErrorNormalization()
	want := &emptypb.Empty{}
	got, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		return want, nil
	})
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if got != want {
		t.Fatalf("response = %v, want handler response", got)
	}
}

func TestValidationRejectsInvalidMessage(t *testing.T) {
	wantErr := errors.New("field x is required")
	interceptor := Validation(func(proto.Message) error { return wantErr })

	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		t.Fatal("handler ran despite validation failure")
		return nil, nil
	})
	if err == nil {
		t.Fatal("Validation passed an invalid message")
	}
	if kiterrors.Code(err) != 400 {
		t.Fatalf("validation error code = %d, want 400", kiterrors.Code(err))
	}
	if !strings.Contains(err.Error(), "field x is required") {
		t.Fatalf("validation error %q drops the validator detail", err.Error())
	}
}

func TestValidationPassesValidMessage(t *testing.T) {
	interceptor := Validation(func(proto.Message) error { return nil })
	ran := false
	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		ran = true
		return &emptypb.Empty{}, nil
	})
	if err != nil {
		t.Fatalf("Validation rejected a valid message: %v", err)
	}
	if !ran {
		t.Fatal("handler did not run for a valid message")
	}
}

func TestValidationNilValidatorSkips(t *testing.T) {
	interceptor := Validation(nil)
	ran := false
	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) {
		ran = true
		return &emptypb.Empty{}, nil
	})
	if err != nil || !ran {
		t.Fatalf("nil validator must skip validation: err=%v ran=%v", err, ran)
	}
}

func TestValidationWithCustomError(t *testing.T) {
	sentinel := kiterrors.New(422, "CUSTOM_VALIDATION", "custom validation failed")
	interceptor := Validation(
		func(proto.Message) error { return errors.New("bad input") },
		WithValidationError(sentinel),
	)
	_, err := interceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(context.Context, any) (any, error) { return nil, nil })
	if kiterrors.Reason(err) != "CUSTOM_VALIDATION" {
		t.Fatalf("reason = %q, want CUSTOM_VALIDATION", kiterrors.Reason(err))
	}
	if !strings.Contains(err.Error(), "bad input") {
		t.Fatalf("custom validation error %q drops the detail", err.Error())
	}
	if !errors.Is(sentinel, sentinel) || sentinel.Message != "custom validation failed" {
		t.Fatalf("sentinel template mutated: %q", sentinel.Message)
	}
}
