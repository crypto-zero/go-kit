package kratos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	authkratos "github.com/crypto-zero/go-kit/auth/kratos"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/crypto-zero/go-kit/sse"
)

// HTTPStreamOption configures a Kratos HTTP-attached SSE stream handler.
type HTTPStreamOption func(*httpStreamConfig)

type httpStreamConfig struct {
	heartbeat time.Duration
	filters   []khttp.FilterFunc
}

// HTTPHeartbeat enables automatic SSE comment frames at interval for one
// Kratos HTTP stream handler. Set interval <= 0 to disable it.
func HTTPHeartbeat(interval time.Duration) HTTPStreamOption {
	return func(c *httpStreamConfig) { c.heartbeat = interval }
}

// HTTPFilter appends Kratos HTTP route filters around one stream endpoint.
func HTTPFilter(filters ...khttp.FilterFunc) HTTPStreamOption {
	return func(c *httpStreamConfig) { c.filters = append(c.filters, filters...) }
}

// RegisterHTTPStream mounts an SSE endpoint on an existing Kratos HTTP
// server. Unlike Server, it does not own a listener: lifecycle, filters,
// route walking, operation selection and service middleware all come from
// the supplied HTTP server.
//
// For GET and HEAD requests, proto.Message inputs are decoded from the query
// string by JSON name (with snake_case fallback). Non-proto GET/HEAD inputs
// use Kratos' configured query decoder. Other methods use Kratos' configured
// body decoder.
func RegisterHTTPStream[Req any](
	srv *khttp.Server,
	method string,
	path string,
	operation string,
	do func(ctx context.Context, req *Req, st *sse.Stream) error,
	opts ...HTTPStreamOption,
) {
	cfg := httpStreamConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	srv.Route("/").Handle(method, path, func(ctx khttp.Context) error {
		req := new(Req)
		if err := bindHTTPStreamRequest(ctx, req); err != nil {
			return err
		}
		if operation != "" {
			khttp.SetOperation(ctx, operation)
		}
		streamCtx, stopStreamCtx := detachHTTPTimeout(ctx)
		defer stopStreamCtx()
		h := ctx.Middleware(func(mctx context.Context, raw any) (any, error) {
			st := sse.NewStream(ctx.Response())
			stopBeat := startHTTPHeartbeat(mctx, st, cfg.heartbeat)
			defer stopBeat()
			if err := do(mctx, raw.(*Req), st); err != nil {
				_ = st.Error(err.Error())
			}
			return nil, nil
		})
		_, err := h(streamCtx, req)
		return err
	}, cfg.filters...)
}

// RegisterHTTPStreamMethod mounts an SSE endpoint for a proto method
// descriptor. The Kratos operation is derived from the method name
// (`/package.Service/Method`) so auth selectors, logging and tracing use the
// same operation identity as generated Kratos HTTP handlers.
func RegisterHTTPStreamMethod[Req any](
	srv *khttp.Server,
	method protoreflect.MethodDescriptor,
	httpMethod string,
	path string,
	do func(ctx context.Context, req *Req, st *sse.Stream) error,
	opts ...HTTPStreamOption,
) {
	RegisterHTTPStream(srv, httpMethod, path, authkratos.OperationName(method), do, opts...)
}

func bindHTTPStreamRequest(ctx khttp.Context, target any) error {
	switch ctx.Request().Method {
	case http.MethodGet, http.MethodHead:
		if msg, ok := target.(proto.Message); ok {
			return decodeProtoQuery(ctx.Request(), msg)
		}
		return ctx.BindQuery(target)
	default:
		return ctx.Bind(target)
	}
}

func startHTTPHeartbeat(ctx context.Context, st *sse.Stream, interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	return st.Heartbeat(ctx, interval)
}

func detachHTTPTimeout(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	done := make(chan struct{})
	go func() {
		select {
		case <-parent.Done():
			if !errors.Is(parent.Err(), context.DeadlineExceeded) {
				cancel()
			}
		case <-done:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			close(done)
			cancel()
		})
	}
}

func decodeProtoQuery(r *http.Request, msg proto.Message) error {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	refl := msg.ProtoReflect()
	fields := refl.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		raw := q.Get(fd.JSONName())
		if raw == "" {
			raw = q.Get(string(fd.Name()))
		}
		if raw == "" {
			continue
		}
		if err := setProtoFieldFromString(refl, fd, raw); err != nil {
			return fmt.Errorf("query %s: %w", fd.JSONName(), err)
		}
	}
	return nil
}

func setProtoFieldFromString(msg protoreflect.Message, fd protoreflect.FieldDescriptor, raw string) error {
	if fd.IsList() || fd.IsMap() {
		return fmt.Errorf("repeated/map fields not supported in query strings")
	}
	switch fd.Kind() {
	case protoreflect.DoubleKind:
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfFloat64(v))
	case protoreflect.FloatKind:
		v, err := strconv.ParseFloat(raw, 32)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfFloat32(float32(v)))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		v, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfInt32(int32(v)))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfUint32(uint32(v)))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfInt64(v))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfUint64(v))
	case protoreflect.BoolKind:
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		msg.Set(fd, protoreflect.ValueOfBool(v))
	case protoreflect.StringKind:
		msg.Set(fd, protoreflect.ValueOfString(raw))
	case protoreflect.EnumKind:
		if i, err := strconv.ParseInt(raw, 10, 32); err == nil {
			msg.Set(fd, protoreflect.ValueOfEnum(protoreflect.EnumNumber(i)))
			return nil
		}
		if ev := fd.Enum().Values().ByName(protoreflect.Name(raw)); ev != nil {
			msg.Set(fd, protoreflect.ValueOfEnum(ev.Number()))
			return nil
		}
		return fmt.Errorf("unknown enum value %q for %s", raw, fd.Enum().FullName())
	default:
		return fmt.Errorf("unsupported field kind %s for query decoding", fd.Kind())
	}
	return nil
}
