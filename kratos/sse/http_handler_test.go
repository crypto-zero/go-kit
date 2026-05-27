package sse_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	ktransport "github.com/go-kratos/kratos/v2/transport"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/protobuf/types/known/durationpb"

	ksse "github.com/crypto-zero/go-kit/kratos/sse"
	"github.com/crypto-zero/go-kit/sse"
)

func TestHTTPStreamHandler_BindsProtoQueryAndStreamsOnKratosHTTP(t *testing.T) {
	srv := khttp.NewServer(khttp.Timeout(0))
	ksse.RegisterHTTPStream(srv, http.MethodGet, "/v1/duration/{seconds}", "/test.Duration/Watch",
		func(_ context.Context, req *durationpb.Duration, st *sse.Stream) error {
			if req.GetSeconds() != 12 || req.GetNanos() != 34 {
				t.Fatalf("request = %ds/%dns, want 12s/34ns", req.GetSeconds(), req.GetNanos())
			}
			_ = st.Write("bound")
			return st.Done()
		},
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/duration/12?nanos=34")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got, want := resp.Header.Get("Content-Type"), "text/event-stream"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "data: bound\n\n") {
		t.Errorf("body missing payload: %q", body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Errorf("body missing done marker: %q", body)
	}
}

func TestHTTPStreamHandler_SetsOperationBeforeMiddleware(t *testing.T) {
	const operation = "/test.Live/Watch"
	seen := make(chan string, 1)
	srv := khttp.NewServer(
		khttp.Timeout(0),
		khttp.Middleware(func(next middleware.Handler) middleware.Handler {
			return func(ctx context.Context, req any) (any, error) {
				tr, ok := ktransport.FromServerContext(ctx)
				if !ok {
					t.Fatal("missing transport")
				}
				seen <- tr.Operation()
				return next(ctx, req)
			}
		}),
	)
	ksse.RegisterHTTPStream(srv, http.MethodGet, "/v1/live", operation,
		func(_ context.Context, _ *durationpb.Duration, st *sse.Stream) error {
			return st.Done()
		},
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/live")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case got := <-seen:
		if got != operation {
			t.Errorf("operation = %q, want %q", got, operation)
		}
	case <-time.After(time.Second):
		t.Fatal("middleware did not run")
	}
}

func TestHTTPStreamHandler_DetachesKratosHTTPTimeout(t *testing.T) {
	srv := khttp.NewServer(khttp.Timeout(20 * time.Millisecond))
	ksse.RegisterHTTPStream(srv, http.MethodGet, "/v1/slow", "/test.Slow/Watch",
		func(ctx context.Context, _ *durationpb.Duration, st *sse.Stream) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(80 * time.Millisecond):
			}
			_ = st.Write("still-open")
			return st.Done()
		},
	)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/slow")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readAll(t, resp.Body)
	if !strings.Contains(body, "data: still-open\n\n") {
		t.Errorf("body missing delayed payload after HTTP timeout: %q", body)
	}
	if !strings.Contains(body, "data: [DONE]\n\n") {
		t.Errorf("body missing done marker: %q", body)
	}
}

func readAll(t *testing.T, r interface {
	Read([]byte) (int, error)
}) string {
	t.Helper()
	var sb strings.Builder
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			return sb.String()
		}
	}
}
