package kratos

import (
	"net/http"

	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

// HTTPPermissiveCORS returns a route filter suitable for browser EventSource
// endpoints that do not use credentials.
func HTTPPermissiveCORS() khttp.FilterFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Cache-Control, Last-Event-ID")
			h.Set("Access-Control-Expose-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
