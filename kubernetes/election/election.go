package election

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	loggerNamed   = "__LOGGER.NAMED__"
	namespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type (
	// StateMachine is the state machine interface.
	StateMachine interface {
		// Name returns the name of the state machine.
		Name() string
		// EnsureMaster ensures the state machine is master.
		EnsureMaster(ctx context.Context) error
		// EnsureSlave ensures the state machine is slave.
		EnsureSlave(ctx context.Context) error
		// Do runs one state machine iteration and returns the delay before the next run.
		Do(ctx context.Context) (after time.Duration)
		// Cleanup releases resources held by the state machine.
		Cleanup()
	}
	// StateMachineRunner runs leader-elected state machines.
	StateMachineRunner interface {
		// Start starts the state machine runner.
		Start(context.Context) error
		// Stop stops the state machine runner.
		Stop(context.Context) error

		// AddMachine adds a state machine.
		AddMachine(machine StateMachine)
	}
)

// StateMachineRunnerImpl is the state machine runner implementation.
type StateMachineRunnerImpl struct {
	ctx         context.Context
	cancel      func()
	closed      atomic.Bool
	cleanupOnce sync.Once

	wg sync.WaitGroup

	cli       *kubernetes.Clientset
	namespace string
	pod       string

	logger *slog.Logger
}

// StateMachiRunnerImpl is deprecated.
//
// Deprecated: Use StateMachineRunnerImpl.
type StateMachiRunnerImpl = StateMachineRunnerImpl

// Start starts the state machine runner.
func (s *StateMachineRunnerImpl) Start(context.Context) error { return nil }

// Stop stops the state machine runner.
func (s *StateMachineRunnerImpl) Stop(context.Context) error {
	s.cleanup()
	return nil
}

// cleanup cleans up the state machine runner.
func (s *StateMachineRunnerImpl) cleanup() {
	s.cleanupOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		s.wg.Wait()
	})
}

// serveMachine serves the state machine.
func (s *StateMachineRunnerImpl) serveMachine(machine StateMachine) {
	defer s.wg.Done()

	name := fmt.Sprintf("state-machine-runner-%s", machine.Name())
	logger := s.logger.With(loggerNamed, name)

	// lease lock name rule: [a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*
	isLeaderChan := make(chan bool, 10)
	leaseLock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("state-machine-runner.%s", machine.Name()),
			Namespace: s.namespace,
		},
		Client: s.cli.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: s.pod,
		},
	}
	lec := leaderelection.LeaderElectionConfig{
		Lock:            leaseLock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				logger.Info("started leading")
				isLeaderChan <- true
			},
			OnStoppedLeading: func() {
				logger.Info("stopped leading")
				isLeaderChan <- false
			},
			OnNewLeader: func(identity string) {
				logger.Info("new leader", "identity", identity)
				if identity != s.pod {
					isLeaderChan <- false
				}
			},
		},
	}
	le, err := leaderelection.NewLeaderElector(lec)
	if err != nil {
		logger.Error("failed to create leader elector", "err", err)
		return
	}

	ctx, cancel := context.WithCancel(s.ctx)

	defer func() { logger.Info("stopped") }()
	defer machine.Cleanup()
	defer cancel()

	go func() { le.Run(ctx) }()

	logger.Info("started")

	var isLeader bool
	ensure := func() bool {
		if isLeader {
			if err := machine.EnsureMaster(ctx); err != nil {
				logger.Error("failed to ensure master", "err", err)
				return false
			}
		} else {
			if err := machine.EnsureSlave(ctx); err != nil {
				logger.Error("failed to ensure slave", "err", err)
				return false
			}
		}
		return true
	}

	select {
	case <-ctx.Done():
		return
	case isLeader = <-isLeaderChan:
		if !ensure() {
			return
		}
	}

	for !s.closed.Load() {
		after := machine.Do(ctx)
		if after <= 0 {
			return
		}
		select {
		case <-time.After(after):
		case <-ctx.Done():
			return
		case isLeader = <-isLeaderChan:
			if !ensure() {
				return
			}
		}
	}
}

func (s *StateMachineRunnerImpl) AddMachine(machine StateMachine) {
	s.wg.Add(1)
	go s.serveMachine(machine)
}

// NewStateMachineRunnerImpl creates a new StateMachineRunner.
func NewStateMachineRunnerImpl(logger *slog.Logger) (StateMachineRunner, func(), error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, err
	}
	cli, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	pod, err := os.Hostname()
	if err != nil {
		return nil, nil, err
	}
	out := &StateMachineRunnerImpl{
		logger:    logger,
		cli:       cli,
		namespace: GetCurrentNamespace(),
		pod:       pod,
	}
	out.ctx, out.cancel = context.WithCancel(context.Background())
	return out, out.cleanup, nil
}

// GetCurrentNamespace returns the current namespace in the kubernetes cluster.
func GetCurrentNamespace() (namespace string) {
	d, err := os.ReadFile(namespacePath)
	if err != nil {
		return ""
	}
	namespace = strings.TrimSpace(string(d))
	return
}
