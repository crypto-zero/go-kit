package sse

import (
	"context"
	"errors"
	"net/http"
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
	_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))

	parent := r.Context()
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	go func() {
		<-parent.Done()
		// Forward only genuine client disconnects. When the parent's Err
		// is DeadlineExceeded the server-wide timer fired — that is the
		// signal we are explicitly detaching from, so the replacement
		// context must stay alive. The cancel func is then released when
		// the handler returns and references drop.
		if !errors.Is(parent.Err(), context.DeadlineExceeded) {
			cancel()
		}
	}()
	return r.WithContext(ctx)
}
