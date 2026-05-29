package gateway

import (
	"context"
	"errors"
	"net/http"
	"time"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

const (
	// DefaultSessionHeader is the default HTTP header carrying the session token.
	DefaultSessionHeader = "X-Session-Token"
)

// SessionCache resolves a user ID from a session token.
type SessionCache interface {
	GetUserIDBySessionID(ctx context.Context, sessionID string, expire time.Duration) (int64, error)
}

// UserProvider loads a user object for an authenticated session.
type UserProvider[T any] interface {
	GetUserByID(ctx context.Context, userID int64) (*T, error)
}

// AuthConfig configures grpc-gateway session authentication.
type AuthConfig[T any] struct {
	Header                string
	SessionTTL            time.Duration
	Cache                 SessionCache
	Provider              UserProvider[T]
	Policy                *OperationPolicy
	NewUserContext        func(context.Context, *T) context.Context
	IsSessionNotFound     func(error) bool
	UnauthenticatedReason string
}

// Auth returns a grpc-gateway middleware that authenticates non-public routes
// and stores the loaded user in the request context via NewUserContext.
func Auth[T any](cfg AuthConfig[T]) runtime.Middleware {
	header := cfg.Header
	if header == "" {
		header = DefaultSessionHeader
	}
	reason := cfg.UnauthenticatedReason
	if reason == "" {
		reason = "INVALID_TOKEN"
	}
	return func(next runtime.HandlerFunc) runtime.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			pattern := PathPattern(r)
			if cfg.Policy != nil && !cfg.Policy.RequiresAuthHTTP(r.Method, pattern) {
				next(w, r, pathParams)
				return
			}
			user, err := authenticate(r.Context(), r.Header.Get(header), cfg)
			if err != nil {
				_, marshaler := runtime.MarshalerForRequest(runtime.NewServeMux(), r)
				if kiterrors.IsUnauthorized(err) {
					err = kiterrors.Unauthorized(reason, "invalid token")
				}
				WriteError(w, marshaler, err)
				return
			}
			next(w, r.WithContext(cfg.NewUserContext(r.Context(), user)), pathParams)
		}
	}
}

func authenticate[T any](ctx context.Context, token string, cfg AuthConfig[T]) (*T, error) {
	if token == "" || cfg.Cache == nil || cfg.Provider == nil || cfg.NewUserContext == nil {
		return nil, kiterrors.Unauthorized("INVALID_TOKEN", "invalid token")
	}
	userID, err := cfg.Cache.GetUserIDBySessionID(ctx, token, cfg.SessionTTL)
	if err != nil {
		if cfg.IsSessionNotFound != nil && cfg.IsSessionNotFound(err) {
			return nil, kiterrors.Unauthorized("INVALID_TOKEN", "invalid token")
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, err
	}
	return cfg.Provider.GetUserByID(ctx, userID)
}
