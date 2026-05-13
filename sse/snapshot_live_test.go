package sse

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStreamSnapshotThenLiveWritesSnapshotEndAndLive(t *testing.T) {
	rec := httptest.NewRecorder()
	st := NewStream(rec)
	live := make(chan int, 2)
	live <- 3
	close(live)

	err := StreamSnapshotThenLive(context.Background(), st, []int{1, 2}, live, SnapshotLiveOptions[int]{
		SnapshotEvent:    "snapshot",
		SnapshotEndEvent: "snapshot-end",
		LiveEvent:        "point",
		ID: func(v int) string {
			return string(rune('a' + v - 1))
		},
		Data: func(v int) (any, error) {
			return map[string]int{"value": v}, nil
		},
	})
	if err != nil {
		t.Fatalf("StreamSnapshotThenLive: %v", err)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"event: snapshot\nid: a\ndata: {\"value\":1}\n\n",
		"event: snapshot\nid: b\ndata: {\"value\":2}\n\n",
		"event: snapshot-end\ndata: {}\n\n",
		"event: point\nid: c\ndata: {\"value\":3}\n\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestStreamSnapshotThenLiveDefaultsToJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	st := NewStream(rec)
	live := make(chan struct {
		Name string `json:"name"`
	})
	close(live)

	err := StreamSnapshotThenLive(context.Background(), st, []struct {
		Name string `json:"name"`
	}{{Name: "one"}}, live, SnapshotLiveOptions[struct {
		Name string `json:"name"`
	}]{})
	if err != nil {
		t.Fatalf("StreamSnapshotThenLive: %v", err)
	}
	if got := rec.Body.String(); !strings.Contains(got, "data: {\"name\":\"one\"}\n\n") {
		t.Fatalf("expected JSON payload, got:\n%s", got)
	}
}
