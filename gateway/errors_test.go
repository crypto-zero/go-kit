package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

func TestWriteErrorRedactsUnknownErrors(t *testing.T) {
	rec := httptest.NewRecorder()

	WriteError(rec, &runtime.JSONPb{}, errors.New("secret database URL"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret database URL") {
		t.Fatalf("unknown error leaked raw message: %s", body)
	}
	if !strings.Contains(body, "internal server error") {
		t.Fatalf("body missing redacted message: %s", body)
	}
}

func TestWriteErrorPreservesKitError(t *testing.T) {
	rec := httptest.NewRecorder()

	WriteError(rec, &runtime.JSONPb{}, kiterrors.BadRequest("BAD_INPUT", "bad input"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "BAD_INPUT") {
		t.Fatalf("body missing reason: %s", body)
	}
}
