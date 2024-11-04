package pprof

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/google/gops/agent"
)

// Pprof is a pprof service.
type Pprof interface{}

// PprofImpl is a pprof service implementation.
type PprofImpl struct{}

// NewPProfImpl returns a new PprofImpl.
// it provides gops agent and pprof service.
func NewPProfImpl() (Pprof, func(), error) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, func() {}, fmt.Errorf("start pprof failed: %v", err)
	}

	log.Println("start pprof service on:", ln.Addr())
	go func() {
		_ = http.Serve(ln, nil)
	}()

	if err := agent.Listen(agent.Options{ShutdownCleanup: false}); err != nil {
		return nil, func() {}, fmt.Errorf("start gops agent failed: %v", err)
	}
	return &PprofImpl{}, func() {}, nil
}
