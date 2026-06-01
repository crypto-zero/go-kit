package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type readinessFunc func(context.Context) error

func (f readinessFunc) Ready(ctx context.Context) error {
	return f(ctx)
}

func TestNewServerAppliesDefaultsAndIndependentTimeouts(t *testing.T) {
	requestTimeout := 3 * time.Second
	readTimeout := 5 * time.Second
	readHeaderTimeout := 7 * time.Second
	writeTimeout := 11 * time.Second
	idleTimeout := 13 * time.Second
	var sawDeadline bool
	srv := NewServer(ServerConfig{
		RequestTimeout:    requestTimeout,
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, sawDeadline = r.Context().Deadline()
	}))

	if srv.network != defaultHTTPNetwork {
		t.Fatalf("network = %q, want %q", srv.network, defaultHTTPNetwork)
	}
	httpServer := srv.HTTPServer()
	if httpServer.Addr != defaultHTTPAddr {
		t.Fatalf("addr = %q, want %q", httpServer.Addr, defaultHTTPAddr)
	}
	if httpServer.ReadTimeout != readTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", httpServer.ReadTimeout, readTimeout)
	}
	if httpServer.ReadHeaderTimeout != readHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", httpServer.ReadHeaderTimeout, readHeaderTimeout)
	}
	if httpServer.WriteTimeout != writeTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", httpServer.WriteTimeout, writeTimeout)
	}
	if httpServer.IdleTimeout != idleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", httpServer.IdleTimeout, idleTimeout)
	}

	httpServer.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !sawDeadline {
		t.Fatal("handler context has no deadline")
	}
}

func TestRegisterProbes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterProbes(mux, ProbeConfig{
		Version: "test",
		Readiness: readinessFunc(func(context.Context) error {
			return nil
		}),
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"version":"test"`) {
		t.Fatalf("healthz body missing version: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRegisterProbesReportsReadinessFailure(t *testing.T) {
	mux := http.NewServeMux()
	RegisterProbes(mux, ProbeConfig{
		Readiness: readinessFunc(func(context.Context) error {
			return errors.New("not ready")
		}),
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "degraded") {
		t.Fatalf("readyz body missing degraded status: %s", rec.Body.String())
	}
}
