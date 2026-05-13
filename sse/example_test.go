package sse_test

import (
	"context"
	"net/http"
	"time"

	"github.com/crypto-zero/go-kit/sse"
)

// ExampleStream_Pump shows the typical streaming handler for a Kratos HTTP
// server. The handler is mounted as a raw net/http handler via srv.Handle,
// bypassing protobuf transcoding so tokens reach the client as soon as the
// upstream goroutine emits them.
//
// Kratos installs a server-wide write deadline through http.Timeout; the
// DetachWriteTimeout call replaces it with a per-connection deadline long
// enough for the SSE stream and detaches the request context from the
// server-injected DeadlineExceeded signal.
func ExampleStream_Pump() {
	const streamTimeout = 300 * time.Second

	handler := func(w http.ResponseWriter, r *http.Request) {
		r = sse.DetachWriteTimeout(w, r, streamTimeout)

		// produceTokens stands in for a biz-layer call that returns the
		// token channel and an error channel.
		chunks, errs := produceTokens(r.Context())

		s := sse.NewStream(w)
		_ = s.Pump(r.Context(), chunks, errs)
	}
	_ = handler
}

// ExampleStream_WriteJSON shows the unary-over-SSE pattern: the handler
// computes a single response, writes it as one data frame, and terminates
// with [DONE]. Useful when the response is structured JSON but the client
// already expects an SSE-formatted endpoint.
func ExampleStream_WriteJSON() {
	const callTimeout = 60 * time.Second

	handler := func(w http.ResponseWriter, r *http.Request) {
		r = sse.DetachWriteTimeout(w, r, callTimeout)

		result, err := compute(r.Context())
		s := sse.NewStream(w)
		if err != nil {
			_ = s.Error(err.Error())
			return
		}
		_ = s.WriteJSON(result)
		_ = s.Done()
	}
	_ = handler
}

func produceTokens(context.Context) (<-chan string, <-chan error) { return nil, nil }
func compute(context.Context) (any, error)                        { return nil, nil }
