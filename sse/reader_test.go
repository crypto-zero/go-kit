package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReaderNext(t *testing.T) {
	r := NewReader(strings.NewReader(": keepalive\nid: 42\nevent: point\nretry: 1500\ndata: {\"ok\":true}\ndata: tail\n\n" +
		"event: next\ndata\n\n" +
		"id:\nevent: reset\ndata: done\n\n"))
	ev, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.ID != "42" || ev.Event != "point" || ev.Retry != 1500*time.Millisecond || ev.Data != "{\"ok\":true}\ntail" {
		t.Fatalf("unexpected event: %#v", ev)
	}
	ev, err = r.Next()
	if err != nil {
		t.Fatalf("Next sticky ID: %v", err)
	}
	if ev.ID != "42" || ev.Event != "next" || ev.Data != "" {
		t.Fatalf("unexpected sticky/no-colon event: %#v", ev)
	}
	ev, err = r.Next()
	if err != nil {
		t.Fatalf("Next reset ID: %v", err)
	}
	if ev.ID != "" || ev.Event != "reset" || ev.Data != "done" {
		t.Fatalf("unexpected reset event: %#v", ev)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next EOF = %v, want io.EOF", err)
	}
}
