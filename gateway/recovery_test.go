package gateway

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

func TestRecoveryWritesRedactedInternalErrorAndLogsPanic(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	mux := runtime.NewServeMux(runtime.WithMiddlewares(Recovery(logger)))
	if err := mux.HandlePath(http.MethodGet, "/panic", func(http.ResponseWriter, *http.Request, map[string]string) {
		panic("secret panic")
	}); err != nil {
		t.Fatalf("HandlePath: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret panic") {
		t.Fatalf("panic leaked to response: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "secret panic") {
		t.Fatalf("panic was not logged: %s", logs.String())
	}
}
