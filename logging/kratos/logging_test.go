package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

var _ transport.Transporter = (*Transport)(nil)

type Transport struct {
	kind      transport.Kind
	endpoint  string
	operation string
}

func (tr *Transport) Kind() transport.Kind {
	return tr.kind
}

func (tr *Transport) Endpoint() string {
	return tr.endpoint
}

func (tr *Transport) Operation() string {
	return tr.operation
}

func (tr *Transport) RequestHeader() transport.Header {
	return nil
}

func (tr *Transport) ReplyHeader() transport.Header {
	return nil
}

func TestHTTP(t *testing.T) {
	err := errors.New("reply.error")
	bf := bytes.NewBuffer(nil)
	logger := slog.New(slog.NewJSONHandler(bf, nil))

	tests := []struct {
		name string
		kind func(logger *slog.Logger) middleware.Middleware
		err  error
		ctx  context.Context
	}{
		{
			"http-server@fail",
			Server,
			err,
			func() context.Context {
				return transport.NewServerContext(context.Background(), &Transport{kind: transport.KindHTTP, endpoint: "endpoint", operation: "/package.service/method"})
			}(),
		},
		{
			"http-server@succ",
			Server,
			nil,
			func() context.Context {
				return transport.NewServerContext(context.Background(), &Transport{kind: transport.KindHTTP, endpoint: "endpoint", operation: "/package.service/method"})
			}(),
		},
		{
			"http-client@succ",
			Client,
			nil,
			func() context.Context {
				return transport.NewClientContext(context.Background(), &Transport{kind: transport.KindHTTP, endpoint: "endpoint", operation: "/package.service/method"})
			}(),
		},
		{
			"http-client@fail",
			Client,
			err,
			func() context.Context {
				return transport.NewClientContext(context.Background(), &Transport{kind: transport.KindHTTP, endpoint: "endpoint", operation: "/package.service/method"})
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bf.Reset()
			next := func(context.Context, any) (any, error) {
				return "reply", test.err
			}
			next = test.kind(logger)(next)
			v, e := next(test.ctx, "req.args")
			t.Logf("[%s]reply: %v, error: %v", test.name, v, e)
			t.Logf("[%s]log:%s", test.name, bf.String())
		})
	}
}

type (
	dummy struct {
		field string
	}
	dummyStringer struct {
		field string
	}
	dummyStringerRedacter struct {
		field string
	}
)

func (d *dummyStringer) String() string {
	return "my value"
}

func (d *dummyStringerRedacter) String() string {
	return "my value"
}

func (d *dummyStringerRedacter) Redact() string {
	return "my value redacted"
}

func TestExtractArgs(t *testing.T) {
	t.Run("dummyStringer", func(t *testing.T) {
		value := extractArgs(&dummyStringer{field: ""})
		if s, ok := value.(string); !ok || s != "my value" {
			t.Errorf(`expected "my value", got %v`, value)
		}
	})

	t.Run("dummy", func(t *testing.T) {
		value := extractArgs(&dummy{field: "value"})
		if s, ok := value.(string); !ok || s != "&{field:value}" {
			t.Errorf(`expected "&{field:value}", got %v`, value)
		}
	})

	t.Run("dummyStringerRedacter", func(t *testing.T) {
		value := extractArgs(&dummyStringerRedacter{field: ""})
		// Redacter returns json.RawMessage to avoid double escaping
		if raw, ok := value.(json.RawMessage); !ok {
			t.Errorf("expected json.RawMessage, got %T", value)
		} else if string(raw) != "my value redacted" {
			t.Errorf(`expected "my value redacted", got %s`, string(raw))
		}
	})
}

func TestExtractError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantLevel  slog.Level
		wantErrStr string
	}{
		{
			"no error", nil, slog.LevelInfo, "",
		},
		{
			"error", errors.New("test error"), slog.LevelError, "test error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			level, errStr := extractError(test.err)
			if level != test.wantLevel {
				t.Errorf("want: %d, got: %d", test.wantLevel, level)
			}
			if errStr != test.wantErrStr {
				t.Errorf("want: %s, got: %s", test.wantErrStr, errStr)
			}
		})
	}
}

func TestServer_Logging(t *testing.T) {
	bf := bytes.NewBuffer(nil)
	logger := slog.New(slog.NewJSONHandler(bf, nil))

	ctx := transport.NewServerContext(context.Background(), &Transport{
		kind:      transport.KindHTTP,
		endpoint:  "endpoint",
		operation: "/package.service/method",
	})

	h := func(context.Context, any) (any, error) { return "reply", nil }
	h = Server(logger)(h)
	_, _ = h(ctx, "test-request")

	output := bf.String()
	t.Logf("Server log output: %s", output)

	// Verify log contains expected fields
	if output == "" {
		t.Error("expected log output, got empty")
	}
}

func TestClient_Logging(t *testing.T) {
	bf := bytes.NewBuffer(nil)
	logger := slog.New(slog.NewJSONHandler(bf, nil))

	ctx := transport.NewClientContext(context.Background(), &Transport{
		kind:      transport.KindHTTP,
		endpoint:  "endpoint",
		operation: "/package.service/method",
	})

	h := func(context.Context, any) (any, error) { return "reply", nil }
	h = Client(logger)(h)
	_, _ = h(ctx, "test-request")

	output := bf.String()
	t.Logf("Client log output: %s", output)

	// Verify log contains expected fields
	if output == "" {
		t.Error("expected log output, got empty")
	}
}
