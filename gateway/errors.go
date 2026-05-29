package gateway

import (
	"context"
	"net/http"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// ErrorHandler returns a grpc-gateway error handler that emits go-kit Error
// payloads instead of google.rpc.Status.
func ErrorHandler() runtime.ErrorHandlerFunc {
	return func(_ context.Context, _ *runtime.ServeMux, marshaler runtime.Marshaler,
		w http.ResponseWriter, _ *http.Request, err error,
	) {
		WriteError(w, marshaler, err)
	}
}

// WriteError writes err as a go-kit Error JSON/proto payload.
func WriteError(w http.ResponseWriter, marshaler runtime.Marshaler, err error) {
	content := kiterrors.FromError(err)
	if content.Status == kiterrors.UnknownCode &&
		(content.Info == nil || content.Info.Reason == kiterrors.UnknownReason) {
		content = kiterrors.InternalServer("INTERNAL_ERROR", "internal server error")
	}
	pbContent := (*kiterrors.PBError)(content)
	body, marshalErr := marshaler.Marshal(pbContent)
	if marshalErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", marshaler.ContentType(pbContent))
	w.WriteHeader(int(content.Status))
	_, _ = w.Write(body)
}
