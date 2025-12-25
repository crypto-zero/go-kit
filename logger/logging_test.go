package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-kratos/kratos/v2/log"
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
	logger := log.NewStdLogger(bf)

	tests := []struct {
		name string
		kind func(logger log.Logger) middleware.Middleware
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
		wantLevel  log.Level
		wantErrStr string
	}{
		{
			"no error", nil, log.LevelInfo, "",
		},
		{
			"error", errors.New("test error"), log.LevelError, "test error",
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

type extractKeyValues [][]any

func (l *extractKeyValues) Log(_ log.Level, kv ...any) error { *l = append(*l, kv); return nil }

func TestServer_CallerPath(t *testing.T) {
	var a extractKeyValues
	logger := log.With(&a, "caller", log.Caller(5)) // report where the helper was called

	// make sure the caller is same
	sameCaller := func(fn middleware.Handler) { _, _ = fn(context.Background(), nil) }

	// caller: [... log inside middleware, fn(context.Background(), nil)]
	h := func(context.Context, any) (a any, e error) { return }
	h = Server(logger)(h)
	sameCaller(h)

	// caller: [... helper.Info("foo"), fn(context.Background(), nil)]
	helper := log.NewHelper(logger)
	sameCaller(func(context.Context, any) (a any, e error) { helper.Info("foo"); return })

	t.Log(a[0])
	t.Log(a[1])
	if a[0][0] != "caller" || a[1][0] != "caller" {
		t.Fatal("caller not found")
	}
	if a[0][1] != a[1][1] {
		t.Fatalf("middleware should have the same caller as log.Helper. middleware: %s, helper: %s", a[0][1], a[1][1])
	}
}

func TestClient_CallerPath(t *testing.T) {
	var a extractKeyValues
	logger := log.With(&a, "caller", log.Caller(5)) // report where the helper was called

	// make sure the caller is same
	sameCaller := func(fn middleware.Handler) { _, _ = fn(context.Background(), nil) }

	// caller: [... log inside middleware, fn(context.Background(), nil)]
	h := func(context.Context, any) (a any, e error) { return }
	h = Client(logger)(h)
	sameCaller(h)

	// caller: [... helper.Info("foo"), fn(context.Background(), nil)]
	helper := log.NewHelper(logger)
	sameCaller(func(context.Context, any) (a any, e error) { helper.Info("foo"); return })

	t.Log(a[0])
	t.Log(a[1])
	if a[0][0] != "caller" || a[1][0] != "caller" {
		t.Fatal("caller not found")
	}
	if a[0][1] != a[1][1] {
		t.Fatalf("middleware should have the same caller as log.Helper. middleware: %s, helper: %s", a[0][1], a[1][1])
	}
}
