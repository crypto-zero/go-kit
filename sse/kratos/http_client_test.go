package kratos_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ksse "github.com/crypto-zero/go-kit/sse"
	ssekratos "github.com/crypto-zero/go-kit/sse/kratos"
)

func TestHTTPClientOpen(t *testing.T) {
	var gotLastEventID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLastEventID = r.Header.Get(ksse.LastEventIDHeader)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("id: 7\nevent: point\ndata: {}\n\n"))
	}))
	defer ts.Close()

	client := ssekratos.NewHTTPClient(ts.URL)
	reader, err := client.Open(context.Background(), http.MethodGet, "/v1/watch?west=1", ssekratos.WithLastEventID("6"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reader.Close()
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
