package kratos_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	kerrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/crypto-zero/go-kit/sse"
	ksse "github.com/crypto-zero/go-kit/sse/kratos"
)

type chatRequest struct {
	Prompt string `json:"prompt"`
}

type profileResponse struct {
	Name string `json:"name"`
}

// authMW is a tiny inline auth middleware that rejects requests missing
// the "X-Token" header by returning a Kratos Unauthorized error.
func authMW(token string) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			if got := tokenFromCtx(ctx); got != token {
				return nil, kerrors.Unauthorized("AUTH", "bad token")
			}
			return next(ctx, req)
		}
	}
}

type tokenKey struct{}

func withToken(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, tokenKey{}, tok)
}

func tokenFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(tokenKey{}).(string)
	return v
}

// tokenFilter copies the X-Token header into ctx so authMW can read it.
// Demonstrates the Filter + Middleware split: Filter touches HTTP-level
// concerns (headers), middleware sees the typed req.
func tokenFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(withToken(r.Context(), r.Header.Get("X-Token")))
		next.ServeHTTP(w, r)
	})
}

func TestStreamHandler_AuthSucceeds(t *testing.T) {
	srv, addr := newServerOnLoopback(t,
		ksse.Filter(tokenFilter),
		ksse.Middleware(authMW("good")),
	)
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(_ context.Context, req *chatRequest, s *sse.Stream) error {
			_ = s.Write("got:" + req.Prompt)
			return s.Done()
		},
	))

	stop := startServer(t, srv)
	defer stop()

	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/chat",
		strings.NewReader(`{"prompt":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token", "good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "data: got:hi\n\n") {
		t.Errorf("body missing chunk: %q", body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Errorf("body missing done: %q", body)
	}
}

func TestStreamHandler_AuthRejects(t *testing.T) {
	srv, addr := newServerOnLoopback(t,
		ksse.Filter(tokenFilter),
		ksse.Middleware(authMW("good")),
	)
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(_ context.Context, _ *chatRequest, s *sse.Stream) error {
			t.Error("handler should not run when auth fails")
			return s.Done()
		},
	))

	stop := startServer(t, srv)
	defer stop()

	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/chat",
		strings.NewReader(`{"prompt":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token", "bad")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); strings.HasPrefix(got, "text/event-stream") {
		t.Errorf("unexpected SSE response on auth failure: %q", got)
	}
}

func TestStreamHandler_DoErrorBecomesSSEEvent(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	sentinel := errors.New("biz blew up")
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(_ context.Context, _ *chatRequest, _ *sse.Stream) error {
			return sentinel
		},
	))

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200 (SSE error rides on 200)", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "event: error") {
		t.Errorf("body missing error event: %q", body)
	}
	if !strings.Contains(body, "biz blew up") {
		t.Errorf("body missing error message: %q", body)
	}
}

func TestStreamHandler_DecodeError(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(context.Context, *chatRequest, *sse.Stream) error {
			t.Error("handler should not run on decode error")
			return nil
		},
	))

	stop := startServer(t, srv)
	defer stop()

	// Malformed JSON.
	resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
		strings.NewReader(`{not json`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == 200 {
		t.Errorf("status = 200, want 4xx/5xx for decode failure")
	}
}

func TestJSONHandler_Roundtrip(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	srv.HandleFunc("POST /v1/profile", ksse.JSONHandler(srv,
		func(_ context.Context, _ *chatRequest) (*profileResponse, error) {
			return &profileResponse{Name: "karma"}, nil
		},
	))

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/v1/profile", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readAll(t, resp.Body)
	if !strings.Contains(body, `data: {"name":"karma"}`) {
		t.Errorf("body missing payload: %q", body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Errorf("body missing done: %q", body)
	}
}

func TestJSONHandler_DoErrorBecomesSSEEvent(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	srv.HandleFunc("POST /v1/profile", ksse.JSONHandler(srv,
		func(_ context.Context, _ *chatRequest) (*profileResponse, error) {
			return nil, kerrors.NotFound("PROFILE", "no profile")
		},
	))

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/v1/profile", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "event: error") {
		t.Errorf("body missing error event: %q", body)
	}
}

func TestStreamHandler_PerHandlerMiddlewareAppends(t *testing.T) {
	calls := make(chan string, 4)
	mark := func(name string) middleware.Middleware {
		return func(next middleware.Handler) middleware.Handler {
			return func(ctx context.Context, req any) (any, error) {
				calls <- name
				return next(ctx, req)
			}
		}
	}
	srv, addr := newServerOnLoopback(t, ksse.Middleware(mark("server")))
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(_ context.Context, _ *chatRequest, s *sse.Stream) error {
			return s.Done()
		},
		mark("handler"),
	))

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	close(calls)
	var order []string
	for s := range calls {
		order = append(order, s)
	}
	want := []string{"server", "handler"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("middleware order = %v, want %v", order, want)
	}
}

func TestStreamHandler_Heartbeat(t *testing.T) {
	srv, addr := newServerOnLoopback(t, ksse.Heartbeat(10*time.Millisecond))
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(ctx context.Context, _ *chatRequest, s *sse.Stream) error {
			_ = s.Write("first")
			// Hold the stream open long enough for several heartbeats.
			select {
			case <-ctx.Done():
			case <-time.After(80 * time.Millisecond):
			}
			return s.Done()
		},
	))

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readAll(t, resp.Body)
	// Expect at least one comment frame between "first" and "[DONE]".
	if !strings.Contains(body, ":\n\n") {
		t.Errorf("body missing heartbeat comment frames: %q", body)
	}
}

func TestServer_ActiveStreams(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	release := make(chan struct{})
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(_ context.Context, _ *chatRequest, s *sse.Stream) error {
			_ = s.Write("hold")
			<-release
			return s.Done()
		},
	))

	stop := startServer(t, srv)

	if got := srv.ActiveStreams(); got != 0 {
		t.Errorf("ActiveStreams before request = %d, want 0", got)
	}

	done := make(chan struct{})
	go func() {
		resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
			strings.NewReader(`{}`))
		if err == nil {
			// Drain to avoid the response goroutine wedging on close.
			_, _ = http.NoBody.Read(make([]byte, 1))
			_ = resp.Body.Close()
		}
		close(done)
	}()

	// Spin until the handler is in flight.
	deadline := time.Now().Add(2 * time.Second)
	for srv.ActiveStreams() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := srv.ActiveStreams(); got != 1 {
		t.Errorf("ActiveStreams during request = %d, want 1", got)
	}
	close(release)
	<-done
	stop()

	if got := srv.ActiveStreams(); got != 0 {
		t.Errorf("ActiveStreams after request = %d, want 0", got)
	}
}

func TestServer_GracefulShutdownUnblocksHandler(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(ctx context.Context, _ *chatRequest, s *sse.Stream) error {
			_ = s.Write("hi")
			// Pump-style: respect ctx so shutdown can drain promptly.
			<-ctx.Done()
			return ctx.Err()
		},
	))

	ctx, cancel := context.WithCancel(context.Background())
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start(ctx) }()

	// Client holds the connection open: it drains the body to keep the
	// server-side r.Context() alive until shutdown explicitly cancels it.
	// (If we closed resp.Body eagerly the server would see a client
	// disconnect instead and we wouldn't exercise shutdown propagation.)
	clientDone := make(chan struct{})
	go func() {
		resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
			strings.NewReader(`{}`))
		if err != nil {
			close(clientDone)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body) // returns when server closes
		_ = resp.Body.Close()
		close(clientDone)
	}()

	// Wait for the stream to register as active.
	deadline := time.Now().Add(2 * time.Second)
	for srv.ActiveStreams() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := srv.ActiveStreams(); got != 1 {
		t.Fatalf("ActiveStreams before shutdown = %d, want 1", got)
	}

	shutdownStart := time.Now()
	shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()
	if err := srv.Stop(shutdownCtx); err != nil {
		t.Errorf("Stop: %v", err)
	}
	elapsed := time.Since(shutdownStart)
	if elapsed > 500*time.Millisecond {
		t.Errorf("Stop took %v, handler did not unblock on shutdown ctx", elapsed)
	}
	<-clientDone
	if err := <-startErr; err != nil {
		t.Errorf("Start: %v", err)
	}
	cancel()
}

func TestErrorEncoder_HonorsKratosCode(t *testing.T) {
	srv, addr := newServerOnLoopback(t,
		ksse.Middleware(func(middleware.Handler) middleware.Handler {
			return func(context.Context, any) (any, error) {
				return nil, kerrors.BadRequest("VALIDATION", "field x missing")
			}
		}),
	)
	srv.HandleFunc("POST /v1/chat", ksse.StreamHandler(srv,
		func(context.Context, *chatRequest, *sse.Stream) error { return nil },
	))

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/v1/chat", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "field x missing") {
		t.Errorf("body missing kratos message: %q", body)
	}
}
