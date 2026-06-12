package pgx

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestOpenDBRejectsUnknownDriver(t *testing.T) {
	_, _, err := OpenDB(context.Background(), DBConfig{Driver: "no-such-driver", Source: "x"}, nil)
	if err == nil {
		t.Fatal("OpenDB with unknown driver returned nil error")
	}
}

func TestIsUniqueViolation(t *testing.T) {
	if !IsUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("IsUniqueViolation(23505) = false, want true")
	}
	if IsUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Fatal("IsUniqueViolation(23503 fk) = true, want false")
	}
	if IsUniqueViolation(errors.New("plain")) {
		t.Fatal("IsUniqueViolation(plain) = true, want false")
	}
	if IsUniqueViolation(nil) {
		t.Fatal("IsUniqueViolation(nil) = true, want false")
	}
}

type fakeRollbacker struct {
	err    error
	called bool
}

func (f *fakeRollbacker) Rollback() error { f.called = true; return f.err }

func TestRollbackOnError(t *testing.T) {
	// No error: no rollback.
	fr := &fakeRollbacker{}
	var nilErr error
	RollbackOnError(fr, &nilErr)
	if fr.called {
		t.Fatal("rollback called with no error")
	}

	// Error present: rollback runs, original error preserved.
	fr = &fakeRollbacker{}
	opErr := errors.New("boom")
	RollbackOnError(fr, &opErr)
	if !fr.called {
		t.Fatal("rollback not called on error")
	}
	if opErr.Error() != "boom" {
		t.Fatalf("error mutated to %v, want boom preserved", opErr)
	}

	// ErrTxDone from rollback is ignored as noise.
	fr = &fakeRollbacker{err: sql.ErrTxDone}
	opErr = errors.New("commit failed")
	RollbackOnError(fr, &opErr)
	if opErr.Error() != "commit failed" {
		t.Fatalf("ErrTxDone joined into error: %v", opErr)
	}

	// A real rollback error is joined.
	fr = &fakeRollbacker{err: errors.New("conn reset")}
	opErr = errors.New("op failed")
	RollbackOnError(fr, &opErr)
	if !errors.Is(opErr, opErr) || opErr.Error() == "op failed" {
		t.Fatalf("real rollback error not joined: %v", opErr)
	}
}
