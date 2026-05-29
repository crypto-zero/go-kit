package gateway

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// Recovery returns a grpc-gateway middleware that converts panics into a
// redacted internal error response and records the panic details for operators.
func Recovery(logger *slog.Logger) runtime.Middleware {
	return func(next runtime.HandlerFunc) runtime.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			defer func() {
				if v := recover(); v != nil {
					if logger != nil {
						logger.ErrorContext(r.Context(), "gateway panic recovered",
							"panic", v,
							"method", r.Method,
							"path", r.URL.Path,
							"operation", PathPattern(r),
							"stack", string(debug.Stack()),
						)
					}
					_, marshaler := runtime.MarshalerForRequest(runtime.NewServeMux(), r)
					WriteError(w, marshaler, errors.New("internal server error"))
				}
			}()
			next(w, r, pathParams)
		}
	}
}
