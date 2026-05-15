package sse

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStream_HeadersAreLazy(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if got := rec.Header().Get("Content-Type"); got != "" {
		t.Errorf("Content-Type before first write = %q, want empty", got)
	}
	if err := s.Write("hello"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := rec.Header().Get("Content-Type"), "text/event-stream"; got != want {
		t.Errorf("Content-Type after Write = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-cache"; got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("X-Accel-Buffering"), "no"; got != want {
		t.Errorf("X-Accel-Buffering = %q, want %q", got, want)
	}
}

func TestStream_StartIdempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	s.Start()
	s.Start()
	if got, want := rec.Code, 200; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
}

func TestStream_WriteFormat(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.Write("hello"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := rec.Body.String(), "data: hello\n\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestStream_WriteEventFull(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	err := s.WriteEvent(Event{
		Event: "delta",
		ID:    "42",
		Data:  "line1\nline2",
		Retry: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	want := "event: delta\nid: 42\nretry: 1500\ndata: line1\ndata: line2\n\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestStream_WriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.WriteJSON(map[string]int{"n": 1}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if got, want := rec.Body.String(), "data: {\"n\":1}\n\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestStream_WriteJSONEvent(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.WriteJSONEvent(Event{Event: "point", ID: "42"}, map[string]int{"n": 1}); err != nil {
		t.Fatalf("WriteJSONEvent: %v", err)
	}
	want := "event: point\nid: 42\ndata: {\"n\":1}\n\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestStream_Error(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.Error("boom"); err != nil {
		t.Fatalf("Error: %v", err)
	}
	want := "event: error\ndata: {\"error\":\"boom\"}\n\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestStream_Done(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.Done(); err != nil {
		t.Fatalf("Done: %v", err)
	}
	if got, want := rec.Body.String(), "data: [DONE]\n\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestPump_CleanFinish(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	chunks := make(chan string, 3)
	errs := make(chan error)
	chunks <- "a"
	chunks <- ""
	chunks <- "b"
	close(chunks)
	if err := s.Pump(context.Background(), chunks, errs); err != nil {
		t.Fatalf("Pump: %v", err)
	}
	got := rec.Body.String()
	want := "data: a\n\ndata: b\n\ndata: [DONE]\n\n"
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestPump_ErrorFromErrCh(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	chunks := make(chan string)
	errs := make(chan error, 1)
	sentinel := errors.New("upstream failure")
	errs <- sentinel
	err := s.Pump(context.Background(), chunks, errs)
	if !errors.Is(err, sentinel) {
		t.Errorf("Pump err = %v, want %v", err, sentinel)
	}
	if !strings.Contains(rec.Body.String(), `"error":"upstream failure"`) {
		t.Errorf("body missing error payload: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), DoneMarker) {
		t.Errorf("body should not contain DONE on error, got %q", rec.Body.String())
	}
}

func TestPump_ErrChClosedSilently(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	chunks := make(chan string)
	errs := make(chan error)
	close(errs)
	if err := s.Pump(context.Background(), chunks, errs); err != nil {
		t.Errorf("Pump on closed errCh = %v, want nil", err)
	}
	if got := rec.Body.String(); got != "" {
		t.Errorf("body = %q, want empty (no headers written either)", got)
	}
}

func TestPump_NilErrReturnsSilently(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	chunks := make(chan string)
	errs := make(chan error, 1)
	errs <- nil
	if err := s.Pump(context.Background(), chunks, errs); err != nil {
		t.Errorf("Pump on nil err = %v, want nil", err)
	}
	if got := rec.Body.String(); got != "" {
		t.Errorf("body = %q, want empty", got)
	}
}

func TestPump_ContextCancel(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	ctx, cancel := context.WithCancel(context.Background())
	chunks := make(chan string)
	errs := make(chan error)
	cancel()
	if err := s.Pump(ctx, chunks, errs); !errors.Is(err, context.Canceled) {
		t.Errorf("Pump err = %v, want context.Canceled", err)
	}
}

func TestStream_Comment(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.Comment("hello"); err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if got, want := rec.Body.String(), ": hello\n\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestStream_CommentEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	if err := s.Comment(""); err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if got, want := rec.Body.String(), ":\n\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestStream_Heartbeat(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)
	stop := s.Heartbeat(context.Background(), 5*time.Millisecond)
	defer stop()

	// Concurrent writes: ensure mutex prevents interleaved frames.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 20; i++ {
			_ = s.Write("token")
			time.Sleep(time.Millisecond)
		}
		close(done)
	}()
	<-done
	stop()

	body := rec.Body.String()
	if !strings.Contains(body, ":\n\n") {
		t.Errorf("expected at least one comment frame, got %q", body)
	}
	if !strings.Contains(body, "data: token\n\n") {
		t.Errorf("expected data frames, got %q", body)
	}
}

func TestStream_HeartbeatNonPositiveIntervalIsNoop(t *testing.T) {
	rec := httptest.NewRecorder()
	s := NewStream(rec)

	stop := s.Heartbeat(context.Background(), 0)
	stop()
	stop()

	if got := rec.Body.String(); got != "" {
		t.Errorf("body = %q, want empty", got)
	}
}

func TestLastEventID(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	r.Header.Set(LastEventIDHeader, "42")
	if got := LastEventID(r); got != "42" {
		t.Errorf("LastEventID(header) = %q, want %q", got, "42")
	}

	r = httptest.NewRequest("GET", "/x", nil)
	if got := LastEventID(r); got != "" {
		t.Errorf("LastEventID(absent) = %q, want empty", got)
	}
}

func TestDetachWriteTimeout_DeadlineDoesNotPropagate(t *testing.T) {
	rec := httptest.NewRecorder()
	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Millisecond))
	defer cancel()
	req := httptest.NewRequest("POST", "/x", nil).WithContext(parent)

	r := DetachWriteTimeout(rec, req, time.Second)
	<-parent.Done()
	// Give the detach goroutine a moment to observe parent.Err().
	time.Sleep(20 * time.Millisecond)

	select {
	case <-r.Context().Done():
		t.Errorf("detached context cancelled on parent DeadlineExceeded; want still alive")
	default:
	}
}

func TestDetachWriteTimeout_PropagatesCancel(t *testing.T) {
	rec := httptest.NewRecorder()
	parent, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/x", nil).WithContext(parent)

	r := DetachWriteTimeout(rec, req, time.Second)
	cancel()

	select {
	case <-r.Context().Done():
	case <-time.After(100 * time.Millisecond):
		t.Errorf("detached context not cancelled when parent was Canceled")
	}
}

func TestDetachWriteTimeout_NonPositiveClearsWriteDeadline(t *testing.T) {
	var got time.Time
	w := deadlineResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		setWriteDeadline: func(t time.Time) error {
			got = t
			return nil
		},
	}
	req := httptest.NewRequest("POST", "/x", nil)

	_ = DetachWriteTimeout(w, req, 0)

	if !got.IsZero() {
		t.Errorf("write deadline = %v, want zero time", got)
	}
}

type deadlineResponseWriter struct {
	http.ResponseWriter
	setWriteDeadline func(time.Time) error
}

func (w deadlineResponseWriter) SetWriteDeadline(t time.Time) error {
	return w.setWriteDeadline(t)
}

func (w deadlineResponseWriter) SetReadDeadline(time.Time) error {
	return nil
}

func (w deadlineResponseWriter) EnableFullDuplex() error {
	return nil
}

func (w deadlineResponseWriter) Flush() error {
	return nil
}

func (w deadlineResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, http.ErrNotSupported
}
