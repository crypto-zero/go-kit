package gateway

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Logging returns a grpc-gateway middleware with standard request logging.
func Logging(logger *slog.Logger) runtime.Middleware {
	return func(next runtime.HandlerFunc) runtime.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			start := time.Now()
			recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next(recorder, r, pathParams)
			pattern := PathPattern(r)
			level := slog.LevelInfo
			if recorder.status >= http.StatusInternalServerError {
				level = slog.LevelError
			}
			logger.Log(r.Context(), level, "gateway",
				"ip", ClientIP(r),
				"device", r.UserAgent(),
				"kind", "server",
				"component", "gateway",
				"method", r.Method,
				"path", r.URL.Path,
				"operation", pattern,
				"code", recorder.status,
				"latency", time.Since(start).Seconds(),
			)
		}
	}
}

// PathPattern returns the matched grpc-gateway path pattern for r.
func PathPattern(r *http.Request) string {
	if r == nil {
		return ""
	}
	if pattern, ok := runtime.HTTPPathPattern(r.Context()); ok {
		return pattern
	}
	if pattern, ok := runtime.HTTPPattern(r.Context()); ok {
		return pattern.String()
	}
	return ""
}

// ClientIP extracts and normalizes the client IP from an HTTP request.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ip := extractIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := extractIP(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return normalizeIP(r.RemoteAddr)
	}
	return normalizeIP(host)
}

func extractIP(headerVal string) string {
	if headerVal == "" {
		return ""
	}
	if idx := strings.IndexByte(headerVal, ','); idx != -1 {
		headerVal = headerVal[:idx]
	}
	return normalizeIP(strings.TrimSpace(headerVal))
}

func normalizeIP(ip string) string {
	if ip == "" {
		return ""
	}
	if idx := strings.IndexByte(ip, '%'); idx != -1 {
		ip = ip[:idx]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return parsed.String()
}
