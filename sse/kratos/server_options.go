package kratos

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/go-kratos/kratos/v2/encoding"
	"github.com/go-kratos/kratos/v2/middleware"
)

// ServerOption configures a Server at construction time.
type ServerOption func(*Server)

// Network sets the listener network (default "tcp").
func Network(network string) ServerOption {
	return func(s *Server) { s.network = network }
}

// Address sets the listener address (default ":0", random port).
func Address(addr string) ServerOption {
	return func(s *Server) { s.address = addr }
}

// Listener supplies a pre-built listener, bypassing Network/Address.
func Listener(lis net.Listener) ServerOption {
	return func(s *Server) { s.lis = lis }
}

// Endpoint overrides the URL advertised via Endpoint(). Use this when the
// listener address (":8080") isn't the externally routable address.
func Endpoint(u *url.URL) ServerOption {
	return func(s *Server) { s.endpoint = u }
}

// TLSConfig configures TLS for the server. When set, Start serves via
// ServeTLS using the certificate(s) from cfg.
func TLSConfig(c *tls.Config) ServerOption {
	return func(s *Server) { s.tlsConf = c }
}

// Codec sets the default codec used by Decode when the request's
// Content-Type does not specify a recognized one. Pass a Kratos codec
// name such as "json" or "proto"; the codec must be registered
// (importing "github.com/go-kratos/kratos/v2/encoding/proto" suffices
// for proto).
//
// Passing a name with no registered codec is a programming error and
// panics — the misconfiguration would otherwise surface as an obscure
// runtime decode failure.
func Codec(name string) ServerOption {
	c := encoding.GetCodec(name)
	if c == nil {
		panic("sse/kratos: codec not registered: " + name)
	}
	return func(s *Server) { s.codec = c }
}

// Logger replaces the default slog.Logger (slog.Default()). A nil logger
// is ignored.
func Logger(l *slog.Logger) ServerOption {
	return func(s *Server) {
		if l != nil {
			s.logger = l
		}
	}
}

// RequestDecoder replaces the request body decoder used by Decode.
func RequestDecoder(dec DecodeRequestFunc) ServerOption {
	return func(s *Server) {
		if dec != nil {
			s.decBody = dec
		}
	}
}

// ErrorEncoder replaces the error encoder used by EncodeError.
func ErrorEncoder(enc EncodeErrorFunc) ServerOption {
	return func(s *Server) {
		if enc != nil {
			s.errEnc = enc
		}
	}
}

// Filter prepends HTTP middleware to the request pipeline. Filters run
// before the route is dispatched, so they may short-circuit auth, set
// cross-cutting headers, or wrap response writing.
func Filter(filters ...FilterFunc) ServerOption {
	return func(s *Server) { s.filters = append(s.filters, filters...) }
}

// Middleware appends Kratos middleware to the chain executed by
// StreamHandler and JSONHandler — between request decoding and stream
// start. Use this for auth, JWT/token verification, schema validation
// and other pre-handler concerns.
//
// These middlewares do NOT wrap the streaming portion of the response;
// any middleware that needs to observe the whole request (tracing,
// metrics, recovery) should be installed as a Filter instead. See the
// package doc for the full rationale.
func Middleware(mws ...middleware.Middleware) ServerOption {
	return func(s *Server) { s.middlewares = append(s.middlewares, mws...) }
}

// ReadHeaderTimeout overrides the time bound on reading request headers
// (default DefaultReadHeaderTimeout). Set to 0 to disable, accepting
// Slowloris risk.
//
// Note: WriteTimeout / IdleTimeout are intentionally not exposed here;
// SSE streams are long-lived and a server-wide write deadline would kill
// them. Per-handler deadlines should be set via http.ResponseController
// inside the handler instead.
func ReadHeaderTimeout(d time.Duration) ServerOption {
	return func(s *Server) { s.readHeaderTimeout = d }
}

// Heartbeat enables automatic SSE comment frames (": \n\n") at the given
// interval on every stream built via StreamHandler or JSONHandler. The
// keepalive is invisible to clients (comments are spec-defined to be
// ignored) but defeats idle-connection timers in upstream proxies
// (nginx, ALB, CloudFlare).
//
// Set to 0 (the default) to disable. Recommended value: 15s — under
// the typical 30-60s proxy idle timeout.
func Heartbeat(interval time.Duration) ServerOption {
	return func(s *Server) { s.heartbeat = interval }
}
