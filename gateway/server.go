package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"
)

const (
	defaultHTTPNetwork      = "tcp"
	defaultHTTPAddr         = ":0"
	defaultReadinessTimeout = 2 * time.Second
	probeStatusField        = "status"
)

// ServerConfig configures a stdlib HTTP server.
type ServerConfig struct {
	Network           string
	Addr              string
	RequestTimeout    time.Duration
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// Server wraps a stdlib HTTP server with network-aware lifecycle methods.
type Server struct {
	server  *http.Server
	network string
}

// NewServer constructs a stdlib HTTP server with go-kit gateway defaults.
func NewServer(cfg ServerConfig, handler http.Handler) *Server {
	network := cfg.Network
	if network == "" {
		network = defaultHTTPNetwork
	}
	addr := cfg.Addr
	if addr == "" {
		addr = defaultHTTPAddr
	}
	if cfg.RequestTimeout > 0 {
		handler = RequestTimeout(cfg.RequestTimeout, handler)
	}
	return &Server{
		network: network,
		server: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadTimeout:       cfg.ReadTimeout,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		},
	}
}

// Start listens and serves HTTP requests.
func (s *Server) Start() error {
	listener, err := net.Listen(s.network, s.server.Addr)
	if err != nil {
		return err
	}
	return s.server.Serve(listener)
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// HTTPServer exposes the underlying stdlib HTTP server for tests and advanced configuration.
func (s *Server) HTTPServer() *http.Server {
	return s.server
}

// RequestTimeout returns a handler that applies timeout to each request context.
func RequestTimeout(timeout time.Duration, next http.Handler) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ReadinessChecker reports whether a service is ready to accept traffic.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

// ProbeConfig configures health and readiness probe endpoints.
type ProbeConfig struct {
	Readiness        ReadinessChecker
	Version          string
	ReadinessTimeout time.Duration
}

// NewRootMux constructs a root mux with probes and the gateway handler.
// Business handlers should be mounted inside gateway so gateway middlewares
// continue to define the transport boundary.
func NewRootMux(gateway http.Handler, probes ProbeConfig) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterProbes(mux, probes)
	mux.Handle("/", gateway)
	return mux
}

// RegisterProbes registers health and readiness probe endpoints on mux.
func RegisterProbes(mux *http.ServeMux, cfg ProbeConfig) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			probeStatusField: "ok",
			"version":        cfg.Version,
		})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		timeout := cfg.ReadinessTimeout
		if timeout <= 0 {
			timeout = defaultReadinessTimeout
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		if cfg.Readiness != nil {
			if err := cfg.Readiness.Ready(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{probeStatusField: "degraded"})
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{probeStatusField: "ok"})
	})
}
