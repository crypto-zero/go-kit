package kratos

import (
	"context"
	"net/http"
	"time"

	khttp "github.com/go-kratos/kratos/v2/transport/http"

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
// GET/HEAD requests decode through ctx.BindQuery; other methods use
// ctx.Bind. Proto messages get the full Kratos form codec handling
// (well-known types, repeated/map fields, nested paths) for free.
func RegisterHTTPStream[Req any](
	srv *khttp.Server,
	method string,
	path string,
	operation string,
	do func(ctx context.Context, req *Req, st *sse.Stream) error,
	opts ...HTTPStreamOption,
) {
	registerHTTPStream(srv, method, path, operation, bindHTTPStreamRequest[Req], do, opts...)
}

func registerHTTPStream[Req any](
	srv *khttp.Server,
	method string,
	path string,
	operation string,
	bind func(khttp.Context, *Req) error,
	do func(ctx context.Context, req *Req, st *sse.Stream) error,
	opts ...HTTPStreamOption,
) {
	cfg := httpStreamConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	srv.Route("/").Handle(method, path, func(ctx khttp.Context) error {
		req := new(Req)
		if err := bind(ctx, req); err != nil {
			return err
		}
		if operation != "" {
			khttp.SetOperation(ctx, operation)
		}
		streamCtx, stopStreamCtx := sse.DetachDeadlineContext(ctx)
		defer stopStreamCtx()
		h := ctx.Middleware(func(mctx context.Context, raw any) (any, error) {
			st := sse.NewStream(ctx.Response())
			stopBeat := st.Heartbeat(mctx, cfg.heartbeat)
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

func bindHTTPStreamRequest[Req any](ctx khttp.Context, target *Req) error {
	if err := ctx.BindVars(target); err != nil {
		return err
	}
	switch ctx.Request().Method {
	case http.MethodGet, http.MethodHead:
		return ctx.BindQuery(target)
	default:
		return ctx.Bind(target)
	}
}
