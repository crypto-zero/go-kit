package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoopRunnerStartsAndStopsLoops(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var loaded atomic.Bool
	started := make(chan struct{})

	runner := NewLoopRunner("test", logger).
		OnStart(func(context.Context) error {
			loaded.Store(true)
			return nil
		}).
		Add("main", func(ctx context.Context) {
			if !loaded.Load() {
				t.Error("loop started before OnStart completed")
			}
			close(started)
			<-ctx.Done()
		})

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, started)

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !strings.Contains(buf.String(), "service stopped") {
		t.Fatalf("logs = %q, want service stopped", buf.String())
	}
}

func TestLoopRunnerRejectsConfigurationAfterStart(t *testing.T) {
	runner := NewLoopRunner("test", testLogger()).Add("main", func(ctx context.Context) {
		<-ctx.Done()
	})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		_ = runner.Stop(context.Background())
	}()

	err := recoverPanic(func() {
		runner.Add("late", func(context.Context) {})
	})
	if !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("panic = %v, want ErrAlreadyStarted", err)
	}
}

func TestLoopRunnerRecoversLoopPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	runner := NewLoopRunner("test", logger).Add("panic", func(context.Context) {
		panic("boom")
	})

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !strings.Contains(buf.String(), "background goroutine panicked") {
		t.Fatalf("logs = %q, want panic log", buf.String())
	}
}

func TestLoopRunnerTickLoop(t *testing.T) {
	ticked := make(chan struct{}, 1)
	runner := NewLoopRunner("test", testLogger()).AddTick("tick", time.Millisecond, func(context.Context) error {
		select {
		case ticked <- struct{}{}:
		default:
		}
		return nil
	})

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, ticked)

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestNewLoopRunnerRejectsMissingName(t *testing.T) {
	err := recoverPanic(func() {
		NewLoopRunner("", testLogger())
	})
	if err == nil || err.Error() != "panic" {
		t.Fatalf("panic = %v, want panic for missing name", err)
	}
}

func TestNewLoopRunnerRejectsMissingLogger(t *testing.T) {
	err := recoverPanic(func() {
		NewLoopRunner("test", nil)
	})
	if err == nil || err.Error() != "panic" {
		t.Fatalf("panic = %v, want panic for missing logger", err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitFor(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel")
	}
}

func recoverPanic(fn func()) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			if e, ok := rec.(error); ok {
				err = e
				return
			}
			err = errors.New("panic")
		}
	}()
	fn()
	return nil
}
