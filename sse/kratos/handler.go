package kratos

import (
	"context"
	"net/http"

	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/crypto-zero/go-kit/sse"
)

// StreamHandler builds an http.HandlerFunc that decodes a typed request,
// runs the Kratos middleware chain over (ctx, *Req), then invokes do
// with a live *sse.Stream.
//
// Lifecycle (in order):
//
//  1. Decode the request body into *Req via srv.Decode. Decode errors
//     are reported via srv.EncodeError — a standard HTTP 4xx/5xx with
//     no SSE bytes written.
//  2. Run the server-wide middleware chain (Middleware option) followed
//     by the per-handler extras, with req exposed to middleware as the
//     `req` argument. Errors here are likewise reported via
//     srv.EncodeError before any streaming starts.
//  3. Create an *sse.Stream and call do. Errors returned by do are
//     emitted as an SSE "error" event; do is responsible for any final
//     Done frame on success.
//
// This is the right helper for auth/JWT verification, schema validation
// (protovalidate), per-request quota checks and similar pre-handler
// concerns. Tracing, recovery and metrics that must observe the full
// stream lifetime should be installed as Filters instead.
func StreamHandler[Req any](
	srv *Server,
	do func(ctx context.Context, req *Req, s *sse.Stream) error,
	mws ...middleware.Middleware,
) http.HandlerFunc {
	chain := srv.chainFor(mws)
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := preStream[Req](srv, chain, w, r)
		if !ok {
			return
		}
		s, end := srv.beginStream(r.Context(), w)
		defer end()
		if err := do(r.Context(), req, s); err != nil {
			_ = s.Error(err.Error())
		}
	}
}

// JSONHandler is the unary sibling of StreamHandler: do produces a
// single response value that is marshaled (via srv.Codec) and emitted
// as one SSE data frame followed by a Done terminator.
//
// Errors returned by do are written as an SSE "error" event — matching
// the convention that clients of an SSE endpoint always parse SSE,
// never raw HTTP errors. Decode and middleware errors still go through
// srv.EncodeError (no SSE bytes written yet).
func JSONHandler[Req any, Resp any](
	srv *Server,
	do func(ctx context.Context, req *Req) (*Resp, error),
	mws ...middleware.Middleware,
) http.HandlerFunc {
	chain := srv.chainFor(mws)
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := preStream[Req](srv, chain, w, r)
		if !ok {
			return
		}
		result, err := do(r.Context(), req)
		s, end := srv.beginStream(r.Context(), w)
		defer end()
		if err != nil {
			_ = s.Error(err.Error())
			return
		}
		data, mErr := srv.Codec().Marshal(result)
		if mErr != nil {
			_ = s.Error(mErr.Error())
			return
		}
		_ = s.Write(string(data))
		_ = s.Done()
	}
}

// preStream runs the request through Decode and the middleware chain.
// On success it returns (req, true). On failure it has already written
// an HTTP error response and returns (_, false).
//
// Middleware sees the decoded req via the `req` argument of
// middleware.Handler. The inner handler is intentionally a no-op:
// streaming runs outside the chain so middleware errors translate to
// real HTTP statuses while no SSE bytes have yet hit the wire.
func preStream[Req any](
	srv *Server, chain middleware.Middleware,
	w http.ResponseWriter, r *http.Request,
) (*Req, bool) {
	req := new(Req)
	if err := srv.Decode(r, req); err != nil {
		srv.EncodeError(w, r, err)
		return nil, false
	}
	h := chain(func(context.Context, any) (any, error) { return nil, nil })
	if _, err := h(r.Context(), req); err != nil {
		srv.EncodeError(w, r, err)
		return nil, false
	}
	return req, true
}

// beginStream constructs an *sse.Stream, starts the configured heartbeat
// (if any), and bumps the active-stream counter. The returned end
// function tears these down in the inverse order — heartbeat first
// (must stop before the response writer is recycled), then the counter.
// Callers should defer end immediately after this call.
func (s *Server) beginStream(ctx context.Context, w http.ResponseWriter) (*sse.Stream, func()) {
	st := sse.NewStream(w)
	stopBeat := s.startHeartbeat(ctx, st)
	s.active.Add(1)
	return st, func() {
		stopBeat()
		s.active.Add(-1)
	}
}

// startHeartbeat fires a periodic comment frame on st when the server
// has Heartbeat enabled. Returns a stop function (a no-op when
// heartbeat is disabled).
func (s *Server) startHeartbeat(ctx context.Context, st *sse.Stream) func() {
	if s.heartbeat <= 0 {
		return func() {}
	}
	return st.Heartbeat(ctx, s.heartbeat)
}

// chainFor composes the middleware chain for one handler: server-wide
// middlewares (outermost) followed by per-handler extras. The returned
// chain does not share backing storage with srv.middlewares, so later
// additions to the server's list cannot retroactively affect handlers
// that have already been built.
func (s *Server) chainFor(extras []middleware.Middleware) middleware.Middleware {
	all := make([]middleware.Middleware, 0, len(s.middlewares)+len(extras))
	all = append(all, s.middlewares...)
	all = append(all, extras...)
	return middleware.Chain(all...)
}
