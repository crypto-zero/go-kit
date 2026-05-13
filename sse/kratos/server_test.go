package kratos_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	ktransport "github.com/go-kratos/kratos/v2/transport"

	"github.com/crypto-zero/go-kit/sse"
	ksse "github.com/crypto-zero/go-kit/sse/kratos"
)

func newServerOnLoopback(t *testing.T, opts ...ksse.ServerOption) (*ksse.Server, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	opts = append([]ksse.ServerOption{ksse.Listener(lis)}, opts...)
	srv := ksse.NewServer(opts...)
	return srv, lis.Addr().String()
}

func startServer(t *testing.T, srv *ksse.Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	startErr := make(chan error, 1)
	go func() { startErr <- srv.Start(ctx) }()
	return func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		if err := srv.Stop(shutdownCtx); err != nil {
			t.Errorf("Stop: %v", err)
		}
		if err := <-startErr; err != nil {
			t.Errorf("Start: %v", err)
		}
		cancel()
	}
}

func TestServer_Name(t *testing.T) {
	srv := ksse.NewServer()
	if got, want := srv.Name(), string(ksse.KindSSE); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestServer_Endpoint(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	u, err := srv.Endpoint()
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if u.Scheme != string(ksse.KindSSE) {
		t.Errorf("scheme = %q, want %q", u.Scheme, ksse.KindSSE)
	}
	if u.Host != addr {
		t.Errorf("host = %q, want %q", u.Host, addr)
	}
}

func TestServer_EndpointOverride(t *testing.T) {
	override := &url.URL{Scheme: "sse", Host: "api.example.com:443"}
	srv := ksse.NewServer(ksse.Endpoint(override))
	got, err := srv.Endpoint()
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if got.String() != override.String() {
		t.Errorf("Endpoint = %q, want %q", got, override)
	}
}

func TestServer_StartAndStreamsEvents(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	srv.HandleFunc("/v1/stream", func(w http.ResponseWriter, _ *http.Request) {
		s := sse.NewStream(w)
		_ = s.Write("hello")
		_ = s.Write("world")
		_ = s.Done()
	})

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Get("http://" + addr + "/v1/stream")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got, want := resp.Header.Get("Content-Type"), "text/event-stream"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	body := readAll(t, resp.Body)
	for _, want := range []string{"data: hello\n\n", "data: world\n\n", "data: [DONE]\n\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nfull body: %q", want, body)
		}
	}
}

func TestServer_TransporterPathTemplate(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	got := make(chan struct {
		kind         ktransport.Kind
		op           string
		ep           string
		pathTemplate string
		hasResponse  bool
	}, 1)
	srv.HandleFunc("/v1/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		tr, ok := ktransport.FromServerContext(r.Context())
		if !ok {
			t.Errorf("no transport in context")
			return
		}
		var pt string
		if ptr, ok := tr.(ksse.Transporter); ok {
			pt = ptr.PathTemplate()
		}
		var hasResp bool
		if _, ok := tr.(ksse.ResponseTransporter); ok {
			hasResp = true
		}
		got <- struct {
			kind         ktransport.Kind
			op           string
			ep           string
			pathTemplate string
			hasResponse  bool
		}{tr.Kind(), tr.Operation(), tr.Endpoint(), pt, hasResp}
		_ = sse.NewStream(w).Done()
	})

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Get("http://" + addr + "/v1/items/42")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	select {
	case v := <-got:
		if v.kind != ksse.KindSSE {
			t.Errorf("Kind = %q, want %q", v.kind, ksse.KindSSE)
		}
		if v.op != "/v1/items/{id}" {
			t.Errorf("Operation = %q, want /v1/items/{id}", v.op)
		}
		if v.pathTemplate != "/v1/items/{id}" {
			t.Errorf("PathTemplate = %q, want /v1/items/{id}", v.pathTemplate)
		}
		if !strings.HasPrefix(v.ep, "sse://") {
			t.Errorf("Endpoint = %q, want sse:// prefix", v.ep)
		}
		if !v.hasResponse {
			t.Errorf("transport does not satisfy ResponseTransporter")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not run")
	}
}

func TestServer_DecodeJSON(t *testing.T) {
	srv, addr := newServerOnLoopback(t)
	type req struct {
		Name string `json:"name"`
	}
	got := make(chan string, 1)
	srv.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		var v req
		if err := srv.Decode(r, &v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got <- v.Name
		_ = sse.NewStream(w).Done()
	})

	stop := startServer(t, srv)
	defer stop()

	body := strings.NewReader(`{"name":"karma"}`)
	resp, err := http.Post("http://"+addr+"/echo", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	select {
	case v := <-got:
		if v != "karma" {
			t.Errorf("decoded name = %q, want karma", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not run")
	}
}

func TestServer_RequestDecoderOverride(t *testing.T) {
	sentinel := errors.New("custom decoder")
	srv, addr := newServerOnLoopback(t,
		ksse.RequestDecoder(func(*http.Request, any) error { return sentinel }),
	)
	srv.HandleFunc("POST /x", func(w http.ResponseWriter, r *http.Request) {
		var v any
		if err := srv.Decode(r, &v); err == nil {
			http.Error(w, "expected sentinel", http.StatusInternalServerError)
			return
		}
		_ = sse.NewStream(w).Done()
	})

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Post("http://"+addr+"/x", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServer_FilterChain(t *testing.T) {
	srv, addr := newServerOnLoopback(t,
		ksse.Filter(
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Outer", "1")
					next.ServeHTTP(w, r)
				})
			},
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Inner", "1")
					next.ServeHTTP(w, r)
				})
			},
		),
	)
	srv.HandleFunc("/f", func(w http.ResponseWriter, _ *http.Request) {
		_ = sse.NewStream(w).Done()
	})

	stop := startServer(t, srv)
	defer stop()

	resp, err := http.Get("http://" + addr + "/f")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Outer"); got != "1" {
		t.Errorf("X-Outer = %q, want 1", got)
	}
	if got := resp.Header.Get("X-Inner"); got != "1" {
		t.Errorf("X-Inner = %q, want 1", got)
	}
}

func TestServer_WalkPattern(t *testing.T) {
	srv := ksse.NewServer()
	srv.HandleFunc("/a", func(http.ResponseWriter, *http.Request) {})
	srv.HandleFunc("POST /b", func(http.ResponseWriter, *http.Request) {})

	var seen []string
	srv.WalkPattern(func(p string) { seen = append(seen, p) })
	want := []string{"/a", "POST /b"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Errorf("WalkPattern visited %v, want %v", seen, want)
	}
}

func TestServer_TLSConfigSelected(t *testing.T) {
	// We only verify the option installs the TLS config; serving TLS
	// requires a real cert that's out of scope for this test.
	srv := ksse.NewServer(ksse.TLSConfig(&tls.Config{}))
	if srv.TLSConfig == nil {
		t.Errorf("TLSConfig not propagated to http.Server")
	}
}

func TestCodecOption_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Codec(unregistered) did not panic")
		}
	}()
	ksse.Codec("nope")
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
