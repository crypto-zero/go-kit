// Package sse implements a minimal Server-Sent Events writer for net/http.
//
// The package is transport-only: it owns the wire format (headers, framing,
// flushing, the [DONE] terminator) and a small helper for draining streaming
// channels. Authentication, request decoding, validation and routing are the
// caller's responsibility.
//
// For a Kratos transport.Server adapter built on top of this package, see
// the sub-package github.com/crypto-zero/go-kit/sse/kratos.
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DoneMarker is the conventional terminator sent as the final data frame of
// an SSE stream. It matches the OpenAI-style protocol that most browser and
// CLI clients already understand.
const DoneMarker = "[DONE]"

// LastEventIDHeader is the HTTP header browsers send on reconnect to resume
// from the last received event.
const LastEventIDHeader = "Last-Event-ID"

// Event is a single SSE event. All fields are optional; an event with only
// Data set produces the common "data: <payload>\n\n" frame.
type Event struct {
	// Event is the event name. When empty, no "event:" field is written and
	// browsers dispatch the frame as the default "message" event.
	Event string
	// ID populates the "id:" field, allowing clients to resume via the
	// Last-Event-ID header on reconnect.
	ID string
	// Data is the event payload. It may contain newlines: each line is
	// emitted as a separate "data:" field per the SSE spec.
	Data string
	// Retry, when non-zero, sets the client's reconnection delay in
	// milliseconds via the "retry:" field.
	Retry time.Duration
}

// Stream writes Server-Sent Events to an HTTP response. Methods are safe for
// concurrent use, allowing a Heartbeat goroutine to coexist with the main
// writer.
type Stream struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	rc      *http.ResponseController
	started bool
}

// NewStream wraps w for SSE output. Headers are not written until the first
// frame is sent (or Start is called explicitly), so callers may still return
// a non-SSE HTTP error after constructing the Stream.
//
// Flushes go through http.ResponseController, which walks any Unwrap()
// chain installed by middleware (metrics wrappers, response recorders) to
// reach the underlying Flusher.
func NewStream(w http.ResponseWriter) *Stream {
	return &Stream{w: w, rc: http.NewResponseController(w)}
}

// Start writes the SSE response headers and the 200 status line. It is safe
// to call multiple times; subsequent calls are no-ops. Callers normally do
// not need to invoke Start directly — any of the Write methods will trigger
// it on first use.
func (s *Stream) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startLocked()
}

func (s *Stream) startLocked() {
	if s.started {
		return
	}
	h := s.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	// Disable proxy buffering (nginx-specific but harmless elsewhere) so
	// frames reach the client as soon as they are flushed.
	h.Set("X-Accel-Buffering", "no")
	s.w.WriteHeader(http.StatusOK)
	s.started = true
}

// Write sends a single default-event data frame and flushes immediately.
func (s *Stream) Write(data string) error {
	return s.WriteEvent(Event{Data: data})
}

// WriteEvent sends a fully specified event and flushes immediately.
func (s *Stream) WriteEvent(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startLocked()

	var b strings.Builder
	if e.Event != "" {
		b.WriteString("event: ")
		b.WriteString(e.Event)
		b.WriteByte('\n')
	}
	if e.ID != "" {
		b.WriteString("id: ")
		b.WriteString(e.ID)
		b.WriteByte('\n')
	}
	if e.Retry > 0 {
		fmt.Fprintf(&b, "retry: %d\n", e.Retry.Milliseconds())
	}
	// Per spec, every newline in the payload starts a new "data:" field;
	// the frame is terminated by a blank line.
	for line := range strings.SplitSeq(e.Data, "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	if _, err := io.WriteString(s.w, b.String()); err != nil {
		return err
	}
	s.flushLocked()
	return nil
}

// WriteJSON marshals v and writes it as a single data frame. The caller is
// responsible for any terminating Done frame.
func (s *Stream) WriteJSON(v any) error {
	return s.WriteJSONEvent(Event{}, v)
}

// WriteJSONEvent marshals v and writes it as a named/id/retry event.
func (s *Stream) WriteJSONEvent(e Event, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sse: marshal json: %w", err)
	}
	e.Data = string(data)
	return s.WriteEvent(e)
}

// Error writes an "error"-named event whose data payload is the JSON object
// {"error": msg}, matching the convention used by most JS EventSource
// consumers.
func (s *Stream) Error(msg string) error {
	return s.WriteJSONEvent(Event{Event: "error"}, map[string]string{"error": msg})
}

// Done sends the DoneMarker as a final data frame, signaling end-of-stream
// to clients that follow the OpenAI-style protocol.
func (s *Stream) Done() error {
	return s.Write(DoneMarker)
}

// Comment writes an SSE comment frame (": text\n\n"). Comments are ignored
// by clients and useful as keepalive packets through proxies that close
// idle connections (nginx, ALB, CloudFlare).
//
// An empty text writes a bare ":\n\n" — the minimal valid keepalive.
func (s *Stream) Comment(text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startLocked()
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		b.WriteByte(':')
		if line != "" {
			b.WriteByte(' ')
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	if _, err := io.WriteString(s.w, b.String()); err != nil {
		return err
	}
	s.flushLocked()
	return nil
}

// Heartbeat starts a goroutine that emits a Comment frame every interval
// until ctx is cancelled or the returned stop function is called.
//
// stop is synchronous: it cancels the ticker and blocks until the
// goroutine has finished its current iteration. Callers MUST invoke
// stop before the underlying http.ResponseWriter is recycled (typically
// by deferring it in the handler) — writing a comment to a reclaimed
// response panics. stop is safe to call multiple times.
//
// Use this for long-lived streams that sit behind proxies with idle
// connection timeouts.
func (s *Stream) Heartbeat(ctx context.Context, interval time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.Comment(""); err != nil {
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// Pump drains chunks into the stream as default data events. It returns
// when:
//
//   - chunks is closed: Done is sent and nil is returned;
//   - errs delivers a non-nil error: that error is forwarded via Error and
//     returned (no Done is sent);
//   - errs is closed: returns nil silently (no Done);
//   - ctx is cancelled: returns ctx.Err() silently (no Done).
//
// Empty chunks are skipped. Callers typically use Pump to relay a
// (<-chan string, <-chan error) pair produced by a streaming biz call.
func (s *Stream) Pump(ctx context.Context, chunks <-chan string, errs <-chan error) error {
	for {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				return s.Done()
			}
			if chunk == "" {
				continue
			}
			if err := s.Write(chunk); err != nil {
				return err
			}
		case err, ok := <-errs:
			if !ok {
				return nil
			}
			if err != nil {
				_ = s.Error(err.Error())
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Stream) flushLocked() {
	// Best-effort: ResponseController.Flush returns http.ErrNotSupported
	// when no Flusher is reachable through the Unwrap chain. SSE without
	// flushing degrades to "client receives nothing until close" — bad,
	// but not something this layer can recover from. Silently ignore.
	_ = s.rc.Flush()
}

// LastEventID returns the value of the Last-Event-ID HTTP header sent by
// EventSource clients on reconnect. Returns "" when absent.
func LastEventID(r *http.Request) string {
	return r.Header.Get(LastEventIDHeader)
}
