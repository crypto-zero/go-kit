package pprof

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"sync"

	"github.com/google/gops/agent"
)

// Pprof is a pprof service.
//
// Deprecated: This broad compatibility type is an alias-shaped service token.
// Consumers should depend on the behavior they need instead of this type.
type Pprof any

// PprofImpl is a pprof service implementation.
type PprofImpl struct {
	listener net.Listener
	once     sync.Once
}

// NewPProfImpl returns a new PprofImpl.
// It provides gops agent and pprof service.
//
// It returns Pprof for backward compatibility with earlier releases.
func NewPProfImpl() (Pprof, func(), error) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, func() {}, fmt.Errorf("start pprof failed: %w", err)
	}

	service := &PprofImpl{listener: ln}
	cleanup := service.Close

	slog.Info("start pprof service", "addr", ln.Addr().String())
	go func() {
		if err := http.Serve(ln, nil); err != nil && !errors.Is(err, net.ErrClosed) {
			slog.Error("pprof service stopped", "err", err)
		}
	}()

	if err := agent.Listen(agent.Options{ShutdownCleanup: false}); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("start gops agent failed: %w", err)
	}
	return service, cleanup, nil
}

// Close stops the pprof service and gops agent.
func (p *PprofImpl) Close() {
	p.once.Do(func() {
		agent.Close()
		if p.listener != nil {
			_ = p.listener.Close()
		}
	})
}
