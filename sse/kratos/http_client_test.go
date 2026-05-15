package kratos_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ksse "github.com/crypto-zero/go-kit/sse"
	ssekratos "github.com/crypto-zero/go-kit/sse/kratos"
)

func TestHTTPClientOpen(t *testing.T) {
	var gotLastEventID string
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLastEventID = r.Header.Get(ksse.LastEventIDHeader)
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("id: 7\nevent: point\ndata: {}\n\n"))
	}))
	defer ts.Close()

	client := ssekratos.NewHTTPClient(ts.URL + "/api")
	reader, err := client.Open(context.Background(), http.MethodGet, "/v1/watch?west=1", nil, ssekratos.WithLastEventID("6"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reader.Close()
	if gotPath != "/api/v1/watch?west=1" {
		t.Fatalf("path = %q, want /api/v1/watch?west=1", gotPath)
	}
	if gotLastEventID != "6" {
		t.Fatalf("Last-Event-ID = %q, want 6", gotLastEventID)
	}
	ev, err := reader.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.ID != "7" || ev.Event != "point" || ev.Data != "{}" {
		t.Fatalf("unexpected event: %#v", ev)
	}
}

func TestHTTPClientOpenSendsJSONBody(t *testing.T) {
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		gotBody = string(body)
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: ok\n\n"))
	}))
	defer ts.Close()

	client := ssekratos.NewHTTPClient(ts.URL)
	reader, err := client.Open(context.Background(), http.MethodPost, "/v1/watch", map[string]string{"name": "alice"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reader.Close()
	if gotBody != `{"name":"alice"}` {
		t.Fatalf("body = %q, want JSON payload", gotBody)
	}
}

func TestHTTPClientOpenStatusErrorIncludesBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"bad token"}`, http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := ssekratos.NewHTTPClient(ts.URL)
	_, err := client.Open(context.Background(), http.MethodGet, "/v1/watch", nil)
	if err == nil {
		t.Fatal("Open err = nil, want error")
	}
	if got := err.Error(); !strings.Contains(got, "401") || !strings.Contains(got, "bad token") {
		t.Fatalf("Open err = %q, want status and body", got)
	}
}

func TestWithHTTPClientNilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewHTTPClient did not panic")
		}
	}()
	_ = ssekratos.NewHTTPClient("http://example.com", ssekratos.WithHTTPClient(nil))
}
