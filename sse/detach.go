package sse

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// DetachWriteTimeout overrides the underlying connection's write deadline
// and returns a request whose context is detached from any server-injected
// deadline.
//
// It addresses a common collision between SSE handlers and HTTP servers that
// install a global write timeout for unary requests (Kratos' http.Timeout
// option is the motivating case). Two things happen:
//
//  1. The connection's write deadline is reset to writeTimeout from now via
//     http.ResponseController, replacing the server-wide value for this
//     connection.
//  2. The request context is replaced with one that cancels only on genuine
//     client disconnect; if the original context's Err is DeadlineExceeded
//     (i.e. the server-wide deadline fired), the replacement is not
//     cancelled.
//
// The replacement context is cancelled when the original context completes
// for any non-deadline reason, so downstream goroutines observing
// ctx.Done() still see client disconnects.
func DetachWriteTimeout(w http.ResponseWriter, r *http.Request, writeTimeout time.Duration) *http.Request {
	rc := http.NewResponseController(w)
	deadline := time.Time{}
	if writeTimeout > 0 {
		deadline = time.Now().Add(writeTimeout)
	}
	_ = rc.SetWriteDeadline(deadline)

	ctx, _ := DetachDeadlineContext(r.Context())
	return r.WithContext(ctx)
}

// DetachDeadlineContext returns a context that keeps parent values but ignores
// parent DeadlineExceeded cancellation. Other parent cancellations, such as a
// client disconnect, are still forwarded.
//
// The returned stop function unregisters the parent callback and cancels the
// detached context. Callers that own a bounded streaming lifecycle should defer
// stop when the stream ends.
func DetachDeadlineContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stopParent := context.AfterFunc(parent, func() {
		if !errors.Is(parent.Err(), context.DeadlineExceeded) {
			cancel()
		}
	})
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			stopParent()
			cancel()
		})
	}
}
