package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReaderNext(t *testing.T) {
	r := NewReader(strings.NewReader(": keepalive\nid: 42\nevent: point\nretry: 1500\ndata: {\"ok\":true}\ndata: tail\n\n"))
	ev, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.ID != "42" || ev.Event != "point" || ev.Retry != 1500*time.Millisecond || ev.Data != "{\"ok\":true}\ntail" {
		t.Fatalf("unexpected event: %#v", ev)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next EOF = %v, want io.EOF", err)
	}
}
