// Package kratos provides a Server-Sent Events transport server that plugs
// into a Kratos application as a first-class transport.Server.
//
// The server owns its own net.Listener and http.ServeMux. Requests it
// serves carry a transport.Transporter with Kind="sse" in their context,
// so Kratos middleware can inspect and act on SSE traffic the same way it
// does for HTTP and gRPC.
//
// Streaming itself is handled by the parent github.com/crypto-zero/go-kit/sse
// package: handlers construct an *sse.Stream from the ResponseWriter and
// write events through its API. This package contributes the Kratos plumbing
// (lifecycle, endpoint registration, codec selection, filter chain) around
// that core.
package kratos

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/go-kratos/kratos/v2/encoding"
	// Register the JSON codec by default; users can pull additional
	// codecs (proto, yaml, xml) by importing them at their main package.
	_ "github.com/go-kratos/kratos/v2/encoding/json"
	"github.com/go-kratos/kratos/v2/middleware"
	ktransport "github.com/go-kratos/kratos/v2/transport"
)

// KindSSE identifies this transport in the Kratos transport registry.
const KindSSE ktransport.Kind = "sse"

// DefaultReadHeaderTimeout is applied when no ReadHeaderTimeout option is
// given. It protects the server from Slowloris-style attacks (clients that
// trickle request headers to hold connections open) without affecting the
// streaming response — write deadlines are managed separately.
const DefaultReadHeaderTimeout = 10 * time.Second

var (
	_ ktransport.Server     = (*Server)(nil)
	_ ktransport.Endpointer = (*Server)(nil)
	_ http.Handler          = (*Server)(nil)
)

// FilterFunc wraps an http.Handler. Filters compose right-to-left around
// the request: the first filter is the outermost wrapper.
type FilterFunc func(http.Handler) http.Handler

// FilterChain composes filters into a single wrapper.
func FilterChain(filters ...FilterFunc) FilterFunc {
	return func(next http.Handler) http.Handler {
		for i := len(filters) - 1; i >= 0; i-- {
			next = filters[i](next)
		}
		return next
	}
}

// DecodeRequestFunc decodes an inbound request body into v.
type DecodeRequestFunc func(*http.Request, any) error

// EncodeErrorFunc reports an error to the client. For SSE handlers the
// default writes an SSE "error" event when headers have not yet been sent,
// otherwise falls through to http.Error.
type EncodeErrorFunc func(http.ResponseWriter, *http.Request, error)

// Server is a Kratos transport.Server that serves Server-Sent Events.
type Server struct {
	*http.Server

	lis      net.Listener
	tlsConf  *tls.Config
	endpoint *url.URL

	network string
	address string

	mux               *http.ServeMux
	codec             encoding.Codec
	logger            *slog.Logger
	filters           []FilterFunc
	middlewares       []middleware.Middleware
	decBody           DecodeRequestFunc
	errEnc            EncodeErrorFunc
	patterns          []string
	readHeaderTimeout time.Duration
	heartbeat         time.Duration

	// shutdownCtx is the parent context handed to every request via
	// http.Server.BaseContext. Stop cancels it before calling Shutdown so
	// long-running SSE handlers observe ctx.Done() and can drain cleanly
	// instead of blocking the shutdown.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// active counts live SSE streams managed by StreamHandler /
	// JSONHandler. Exposed via ActiveStreams.
	active atomic.Int64
}

// NewServer constructs a Server. With no options it listens on a random
// TCP port, uses the JSON codec, and serves plaintext HTTP.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		network:           "tcp",
		address:           ":0",
		mux:               http.NewServeMux(),
		codec:             encoding.GetCodec("json"),
		logger:            slog.Default(),
		decBody:           DefaultRequestDecoder,
		errEnc:            DefaultErrorEncoder,
		readHeaderTimeout: DefaultReadHeaderTimeout,
	}
	for _, o := range opts {
		o(s)
	}
	s.Server = &http.Server{
		Handler:           FilterChain(s.filters...)(http.HandlerFunc(s.dispatch)),
		TLSConfig:         s.tlsConf,
		ReadHeaderTimeout: s.readHeaderTimeout,
	}
	return s
}

// Name returns the transport kind, "sse".
func (s *Server) Name() string { return string(KindSSE) }

// Endpoint returns the address the server is (or will be) listening on,
// scheme "sse://", suitable for service-registry advertisement.
func (s *Server) Endpoint() (*url.URL, error) {
	if err := s.listenAndEndpoint(); err != nil {
		return nil, err
	}
	return s.endpoint, nil
}

// Codec returns the codec configured for request/response payloads.
func (s *Server) Codec() encoding.Codec { return s.codec }

// Start opens the listener (if not already) and serves until Stop is
// called or the listener fails. It implements transport.Server.
func (s *Server) Start(ctx context.Context) error {
	if err := s.listenAndEndpoint(); err != nil {
		return err
	}
	// Build a cancellable child context that Stop will tear down before
	// http.Server.Shutdown runs. Handlers receive this ctx via
	// r.Context(), so a Pump select-on-Done unblocks promptly during
	// shutdown rather than holding the connection until its own write
	// deadline expires.
	s.shutdownCtx, s.shutdownCancel = context.WithCancel(ctx)
	s.BaseContext = func(net.Listener) context.Context { return s.shutdownCtx }
	s.logger.InfoContext(ctx, "sse server listening", "addr", s.lis.Addr().String())

	var err error
	if s.tlsConf != nil {
		err = s.ServeTLS(s.lis, "", "")
	} else {
		err = s.Serve(s.lis)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop gracefully shuts the server down. It first cancels the
// shutdown-aware context that every handler receives — long-running SSE
// streams that observe ctx.Done() will exit promptly — then calls
// http.Server.Shutdown to wait for in-flight requests to complete. If
// ctx expires before drainage finishes, Stop force-closes connections,
// matching the Kratos HTTP server's behavior.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.InfoContext(ctx, "sse server stopping",
		"active_streams", s.ActiveStreams())
	if s.shutdownCancel != nil {
		s.shutdownCancel()
	}
	if err := s.Shutdown(ctx); err != nil {
		if ctx.Err() != nil {
			s.logger.WarnContext(ctx, "sse server force-closing after shutdown timeout")
			return s.Close()
		}
		return err
	}
	return nil
}

// ActiveStreams reports the number of SSE streams currently in flight
// through StreamHandler or JSONHandler. Handlers mounted via plain
// Handle / HandleFunc are not counted.
func (s *Server) ActiveStreams() int64 { return s.active.Load() }

// Handle mounts an http.Handler at pattern. Pattern syntax follows
// net/http.ServeMux (Go 1.22+ "METHOD /path/{var}" form).
func (s *Server) Handle(pattern string, h http.Handler) {
	s.mux.Handle(pattern, h)
	s.patterns = append(s.patterns, pattern)
}

// HandleFunc mounts an http.HandlerFunc at pattern.
func (s *Server) HandleFunc(pattern string, h http.HandlerFunc) {
	s.Handle(pattern, h)
}

// WalkPattern visits every pattern registered with Handle/HandleFunc.
// The order matches registration order.
func (s *Server) WalkPattern(fn func(pattern string)) {
	for _, p := range s.patterns {
		fn(p)
	}
}

// Decode reads r.Body and unmarshals it via the configured request
// decoder (set with RequestDecoder; defaults to DefaultRequestDecoder).
func (s *Server) Decode(r *http.Request, v any) error {
	return s.decBody(r, v)
}

// EncodeError reports err to the client via the configured error
// encoder.
func (s *Server) EncodeError(w http.ResponseWriter, r *http.Request, err error) {
	s.errEnc(w, r, err)
}

// ServeHTTP runs the filter chain around the routing dispatch.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handler.ServeHTTP(w, r)
}

// dispatch is the innermost handler invoked after filters run. It installs
// the SSE transport.Transporter into the request context and dispatches
// the request via the mux.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	// Resolve the matched pattern (e.g. "/v1/sse/chat:stream") so
	// middleware that inspects Operation sees the route template rather
	// than the request-specific path.
	_, pattern := s.mux.Handler(r)

	tr := &Transport{
		endpoint:     s.endpointString(),
		operation:    pattern,
		pathTemplate: pattern,
		request:      r,
		response:     w,
		reqHeader:    headerCarrier(r.Header),
		replyHeader:  headerCarrier(w.Header()),
	}
	r = r.WithContext(ktransport.NewServerContext(r.Context(), tr))
	s.mux.ServeHTTP(w, r)
}

func (s *Server) endpointString() string {
	if s.endpoint == nil {
		return ""
	}
	return s.endpoint.String()
}

func (s *Server) listenAndEndpoint() error {
	if s.lis == nil {
		lis, err := net.Listen(s.network, s.address)
		if err != nil {
			return err
		}
		s.lis = lis
	}
	if s.endpoint == nil {
		s.endpoint = &url.URL{Scheme: string(KindSSE), Host: s.lis.Addr().String()}
	}
	return nil
}
