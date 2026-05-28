// Package lifecycle provides helpers for service lifecycles.
package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// ErrAlreadyStarted reports a runner configuration change after Start.
var ErrAlreadyStarted = errors.New("lifecycle: runner already started")

// Service is the common lifecycle interface used by Kratos servers.
type Service interface {
	Start(context.Context) error
	Stop(context.Context) error
}

// LoopRunner manages a group of background loops.
type LoopRunner interface {
	Service

	// OnStart registers a callback that runs during Start before any loops are
	// spawned. Calling OnStart twice overrides the previous callback.
	OnStart(func(context.Context) error) LoopRunner

	// Add registers a loop to spawn during Start.
	Add(name string, fn func(context.Context)) LoopRunner

	// AddTick registers a periodic loop that invokes fn every interval.
	AddTick(name string, interval time.Duration, fn func(context.Context) error) LoopRunner
}

type namedLoop struct {
	name string
	fn   func(context.Context)
}

type loopRunner struct {
	name   string
	logger *slog.Logger

	mu      sync.Mutex
	onStart func(context.Context) error
	loops   []namedLoop
	cancel  context.CancelFunc
	started bool

	wg sync.WaitGroup
}

// NewLoopRunner constructs a runner scoped to name.
func NewLoopRunner(name string, logger *slog.Logger) LoopRunner {
	if logger == nil {
		panic("lifecycle: logger is nil")
	}
	if name == "" {
		panic("lifecycle: service name is empty")
	}
	return &loopRunner{
		name:   name,
		logger: logger.With("service", name),
	}
}

func (r *loopRunner) OnStart(fn func(context.Context) error) LoopRunner {
	if err := r.configure(func() {
		r.onStart = fn
	}); err != nil {
		panic(err)
	}
	return r
}

func (r *loopRunner) Add(name string, fn func(context.Context)) LoopRunner {
	if name == "" {
		panic("lifecycle: loop name is empty")
	}
	if fn == nil {
		panic("lifecycle: loop function is nil")
	}
	if err := r.configure(func() {
		r.loops = append(r.loops, namedLoop{name: name, fn: fn})
	}); err != nil {
		panic(err)
	}
	return r
}

func (r *loopRunner) AddTick(name string, interval time.Duration, fn func(context.Context) error) LoopRunner {
	if interval <= 0 {
		panic("lifecycle: tick interval must be positive")
	}
	if fn == nil {
		panic("lifecycle: tick function is nil")
	}
	return r.Add(name, func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := fn(ctx); err != nil {
					r.logger.ErrorContext(ctx, "loop tick failed", "loop", name, "err", err)
				}
			}
		}
	})
}

// Start implements Service.
func (r *loopRunner) Start(ctx context.Context) error {
	runCtx, onStart, loops, err := r.start()
	if err != nil {
		return err
	}
	if onStart != nil {
		if err := onStart(ctx); err != nil {
			_ = r.Stop(context.Background())
			return err
		}
	}
	for _, l := range loops {
		r.spawn(runCtx, l.name, l.fn)
	}
	r.logger.InfoContext(ctx, "service started", "loops", len(loops))
	return nil
}

// Stop implements Service.
func (r *loopRunner) Stop(ctx context.Context) error {
	cancel := r.stop()
	if cancel == nil {
		return nil
	}
	cancel()

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		r.finishStop()
		close(done)
	}()

	select {
	case <-done:
		r.logger.InfoContext(ctx, "service stopped")
	case <-ctx.Done():
		r.logger.WarnContext(ctx, "stop deadline exceeded, goroutines may still be running")
	}
	return nil
}

func (r *loopRunner) configure(fn func()) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return ErrAlreadyStarted
	}
	fn()
	return nil
}

func (r *loopRunner) start() (context.Context, func(context.Context) error, []namedLoop, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return nil, nil, nil, ErrAlreadyStarted
	}
	runCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.started = true
	return runCtx, r.onStart, append([]namedLoop(nil), r.loops...), nil
}

func (r *loopRunner) stop() context.CancelFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	cancel := r.cancel
	r.cancel = nil
	return cancel
}

func (r *loopRunner) finishStop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = false
}

func (r *loopRunner) spawn(ctx context.Context, name string, fn func(context.Context)) {
	r.wg.Go(func() {
		defer func() {
			if rec := recover(); rec != nil {
				r.logger.ErrorContext(ctx, "background goroutine panicked", "loop", name, "panic", rec)
			}
		}()
		if fn == nil {
			return
		}
		fn(ctx)
	})
}
