package election

import (
	"context"
	"testing"
)

func TestStateMachineRunnerStopIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &StateMachineRunnerImpl{
		ctx:    ctx,
		cancel: cancel,
	}

	if err := runner.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := runner.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	select {
	case <-ctx.Done():
	default:
		t.Fatal("Stop did not cancel runner context")
	}
}
