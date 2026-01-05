package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// =============================================================================
// Mock Types for Testing
// =============================================================================

// mockRedacter implements the Redacter interface
type mockRedacter struct {
	Value    string
	Password string
}

func (m *mockRedacter) Redact() string {
	return fmt.Sprintf(`{"value":"%s","password":"***"}`, m.Value)
}

// mockStringer implements fmt.Stringer
type mockStringer struct {
	Value string
}

func (m *mockStringer) String() string {
	return "Stringer: " + m.Value
}

// plainStruct is a plain struct without any interface
type plainStruct struct {
	Name string
	Age  int
}

// mockTransporter implements transport.Transporter for server context
type mockTransporter struct {
	kind      transport.Kind
	operation string
}

func (m *mockTransporter) Kind() transport.Kind { return m.kind }
func (m *mockTransporter) Endpoint() string     { return "localhost:8080" }
func (m *mockTransporter) Operation() string    { return m.operation }
func (m *mockTransporter) RequestHeader() transport.Header {
	return &mockHeader{}
}
func (m *mockTransporter) ReplyHeader() transport.Header {
	return &mockHeader{}
}

type mockHeader struct{}

func (m *mockHeader) Get(key string) string        { return "" }
func (m *mockHeader) Set(key string, value string) {}
func (m *mockHeader) Add(key string, value string) {}
func (m *mockHeader) Keys() []string               { return nil }
func (m *mockHeader) Values(key string) []string   { return nil }

// =============================================================================
// extractArgs Tests
// =============================================================================

func TestExtractArgs_Redacter(t *testing.T) {
	req := &mockRedacter{Value: "test", Password: "secret123"}
	result := extractArgs(req, false)

	raw, ok := result.(json.RawMessage)
	if !ok {
		t.Fatalf("Expected json.RawMessage, got %T", result)
	}

	str := string(raw)
	if !strings.Contains(str, `"value":"test"`) {
		t.Errorf("Expected value to be preserved, got: %s", str)
	}
	if !strings.Contains(str, `"password":"***"`) {
		t.Errorf("Expected password to be masked, got: %s", str)
	}
	if strings.Contains(str, "secret123") {
		t.Errorf("Password should not contain original value, got: %s", str)
	}
}

func TestExtractArgs_Redacter_SkipRedact(t *testing.T) {
	req := &mockRedacter{Value: "test", Password: "secret123"}
	// When skipRedact is true, it shouldn't use Redact(), but fall through to fmt.Sprintf or other logic.
	// Since mockRedacter is a struct pointer, it likely falls to fmt.Sprintf("%+v", args) if not implementing other interfaces.
	// Let's verify what mockRedacter does when not cast to Redacter.
	// It doesn't implement fmt.Stringer or proto.Message. So it should hit default case: fmt.Sprintf("%+v", args)

	result := extractArgs(req, true)

	str, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string for skipped redact, got %T", result)
	}

	// %+v on struct pointer often prints &{Field:Value ...}
	if !strings.Contains(str, "secret123") {
		t.Errorf("Expected original password to be visible when skipping redact, got: %s", str)
	}
}

func TestExtractArgs_ProtoMessage(t *testing.T) {
	msg := wrapperspb.String("hello world")
	result := extractArgs(msg, false)

	raw, ok := result.(json.RawMessage)
	if !ok {
		t.Fatalf("Expected json.RawMessage for proto.Message, got %T", result)
	}

	str := string(raw)
	if !strings.Contains(str, "hello world") {
		t.Errorf("Expected proto message content, got: %s", str)
	}
}

func TestExtractArgs_Stringer(t *testing.T) {
	s := &mockStringer{Value: "hello"}
	result := extractArgs(s, false)

	str, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string for Stringer, got %T", result)
	}

	if str != "Stringer: hello" {
		t.Errorf("Expected 'Stringer: hello', got: %s", str)
	}
}

func TestExtractArgs_PlainStruct(t *testing.T) {
	plain := &plainStruct{Name: "John", Age: 30}
	result := extractArgs(plain, false)

	str, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string for plain struct, got %T", result)
	}

	if !strings.Contains(str, "John") || !strings.Contains(str, "30") {
		t.Errorf("Expected struct fields in output, got: %s", str)
	}
}

func TestExtractArgs_Nil(t *testing.T) {
	result := extractArgs(nil, false)
	str, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string for nil, got %T", result)
	}
	if str != "<nil>" {
		t.Errorf("Expected '<nil>', got: %s", str)
	}
}

// =============================================================================
// extractError Tests
// =============================================================================

func TestExtractError_Nil(t *testing.T) {
	level, stack := extractError(nil)

	if level != slog.LevelInfo {
		t.Errorf("Expected LevelInfo for nil error, got: %v", level)
	}
	if stack != "" {
		t.Errorf("Expected empty stack for nil error, got: %s", stack)
	}
}

func TestExtractError_WithError(t *testing.T) {
	err := fmt.Errorf("something went wrong")
	level, stack := extractError(err)

	if level != slog.LevelError {
		t.Errorf("Expected LevelError for error, got: %v", level)
	}
	if !strings.Contains(stack, "something went wrong") {
		t.Errorf("Expected error message in stack, got: %s", stack)
	}
}

func TestExtractError_KratosError(t *testing.T) {
	err := errors.New(400, "BAD_REQUEST", "invalid input")
	level, stack := extractError(err)

	if level != slog.LevelError {
		t.Errorf("Expected LevelError for kratos error, got: %v", level)
	}
	if !strings.Contains(stack, "invalid input") {
		t.Errorf("Expected error message in stack, got: %s", stack)
	}
}

// =============================================================================
// Server Middleware Tests
// =============================================================================

func TestServer_Success(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := Server(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return &mockRedacter{Value: "response", Password: "secret"}, nil
	}

	wrapped := mw(handler)

	// Create context with transport info
	ctx := transport.NewServerContext(context.Background(), &mockTransporter{
		kind:      transport.KindHTTP,
		operation: "/api/v1/test",
	})

	req := &mockRedacter{Value: "request", Password: "password123"}
	reply, err := wrapped(ctx, req)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if reply == nil {
		t.Fatal("Expected reply, got nil")
	}

	// Check log output
	logOutput := buf.String()
	if !strings.Contains(logOutput, "server request") {
		t.Errorf("Expected 'server request' in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "/api/v1/test") {
		t.Errorf("Expected operation in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "http") {
		t.Errorf("Expected http kind in log, got: %s", logOutput)
	}
	// Verify password is masked in args
	if strings.Contains(logOutput, "password123") {
		t.Errorf("Request password should be masked in log, got: %s", logOutput)
	}
	if strings.Contains(logOutput, `"password":"secret"`) {
		t.Errorf("Reply password should be masked in log, got: %s", logOutput)
	}
}

func TestServer_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := Server(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return nil, errors.New(400, "BAD_REQUEST", "invalid input")
	}

	wrapped := mw(handler)

	ctx := transport.NewServerContext(context.Background(), &mockTransporter{
		kind:      transport.KindGRPC,
		operation: "/grpc.test/Method",
	})

	_, err := wrapped(ctx, "test request")

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "ERROR") {
		t.Errorf("Expected ERROR level in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "400") {
		t.Errorf("Expected error code 400 in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "BAD_REQUEST") {
		t.Errorf("Expected reason in log, got: %s", logOutput)
	}
}

func TestServer_WithoutTransport(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := Server(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	wrapped := mw(handler)

	// Context without transport info
	ctx := context.Background()
	_, err := wrapped(ctx, "request")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "server request") {
		t.Errorf("Expected 'server request' in log, got: %s", logOutput)
	}
}

// =============================================================================
// Client Middleware Tests
// =============================================================================

func TestClient_Success(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := Client(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return "response", nil
	}

	wrapped := mw(handler)

	ctx := transport.NewClientContext(context.Background(), &mockTransporter{
		kind:      transport.KindHTTP,
		operation: "/api/external/call",
	})

	reply, err := wrapped(ctx, "request")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if reply == nil {
		t.Fatal("Expected reply, got nil")
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "client request") {
		t.Errorf("Expected 'client request' in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "/api/external/call") {
		t.Errorf("Expected operation in log, got: %s", logOutput)
	}
}

func TestClient_WithError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := Client(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return nil, errors.New(500, "INTERNAL_ERROR", "service unavailable")
	}

	wrapped := mw(handler)

	ctx := transport.NewClientContext(context.Background(), &mockTransporter{
		kind:      transport.KindGRPC,
		operation: "/grpc.external/Call",
	})

	_, err := wrapped(ctx, "request")

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "ERROR") {
		t.Errorf("Expected ERROR level in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "500") {
		t.Errorf("Expected error code 500 in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "INTERNAL_ERROR") {
		t.Errorf("Expected reason in log, got: %s", logOutput)
	}
}

// =============================================================================
// Redacter Interface Tests
// =============================================================================

func TestRedacterInterface(t *testing.T) {
	// Verify mockRedacter implements Redacter
	var _ Redacter = (*mockRedacter)(nil)

	r := &mockRedacter{Value: "test", Password: "secret"}
	result := r.Redact()

	var parsed map[string]string
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Redact() should return valid JSON: %v", err)
	}

	if parsed["value"] != "test" {
		t.Errorf("Expected value 'test', got: %s", parsed["value"])
	}
	if parsed["password"] != "***" {
		t.Errorf("Expected masked password, got: %s", parsed["password"])
	}
}

// =============================================================================
// Middleware Signature Tests
// =============================================================================

func TestServerReturnsMiddleware(t *testing.T) {
	logger := slog.Default()
	mw := Server(logger)

	if mw == nil {
		t.Fatal("Server() should return a middleware")
	}

	// Verify it's a valid middleware type
	var _ middleware.Middleware = mw
}

func TestClientReturnsMiddleware(t *testing.T) {
	logger := slog.Default()
	mw := Client(logger)

	if mw == nil {
		t.Fatal("Client() should return a middleware")
	}

	// Verify it's a valid middleware type
	var _ middleware.Middleware = mw
}

// =============================================================================
// Latency Logging Tests
// =============================================================================

func TestServer_LogsLatency(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	mw := Server(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	wrapped := mw(handler)
	_, _ = wrapped(context.Background(), "req")

	logOutput := buf.String()
	if !strings.Contains(logOutput, "latency") {
		t.Errorf("Expected 'latency' in log, got: %s", logOutput)
	}
}

func TestClient_LogsLatency(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	mw := Client(logger)

	handler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	wrapped := mw(handler)
	_, _ = wrapped(context.Background(), "req")

	logOutput := buf.String()
	if !strings.Contains(logOutput, "latency") {
		t.Errorf("Expected 'latency' in log, got: %s", logOutput)
	}
}

func TestServer_WithSkipRedact(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Use WithSkipRedact option
	mw := Server(logger, WithSkipRedact())

	handler := func(ctx context.Context, req any) (any, error) {
		return &mockRedacter{Value: "response", Password: "secret"}, nil
	}

	wrapped := mw(handler)

	ctx := transport.NewServerContext(context.Background(), &mockTransporter{
		kind:      transport.KindHTTP,
		operation: "/api/v1/test",
	})

	req := &mockRedacter{Value: "request", Password: "password123"}
	_, err := wrapped(ctx, req)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	logOutput := buf.String()

	// When skipping redact, we don't use Redact() method, so json structure might be different or just default struct print.
	// But definitively check for presence of sensitive data.
	if !strings.Contains(logOutput, "password123") {
		t.Errorf("Request password should be visible in log when skipping redact, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "secret") {
		t.Errorf("Reply password should be visible in log when skipping redact, got: %s", logOutput)
	}
}

func TestClient_WithSkipRedact(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Use WithSkipRedact option
	mw := Client(logger, WithSkipRedact())

	handler := func(ctx context.Context, req any) (any, error) {
		return &mockRedacter{Value: "response", Password: "secret"}, nil
	}

	wrapped := mw(handler)

	ctx := transport.NewClientContext(context.Background(), &mockTransporter{
		kind:      transport.KindHTTP,
		operation: "/api/external/call",
	})

	req := &mockRedacter{Value: "request", Password: "password123"}
	_, err := wrapped(ctx, req)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	logOutput := buf.String()

	if !strings.Contains(logOutput, "password123") {
		t.Errorf("Request password should be visible in log when skipping redact, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "secret") {
		t.Errorf("Reply password should be visible in log when skipping redact, got: %s", logOutput)
	}
}
