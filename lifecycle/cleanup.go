package lifecycle

// CleanupStack collects cleanup functions and runs them in last-in-first-out
// order, mirroring deferred teardown for dependencies assembled at startup
// (close the database after the cache that depends on it, etc.). The zero
// value is ready to use.
type CleanupStack struct {
	funcs []func()
}

// Add registers a cleanup function. A nil function is ignored so callers can
// pass a constructor's cleanup return value without a nil check.
func (s *CleanupStack) Add(cleanup func()) {
	if cleanup != nil {
		s.funcs = append(s.funcs, cleanup)
	}
}

// Run executes the registered cleanups in reverse registration order.
func (s *CleanupStack) Run() {
	for i := len(s.funcs) - 1; i >= 0; i-- {
		s.funcs[i]()
	}
}
