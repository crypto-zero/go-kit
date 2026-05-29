package gateway

import (
	"context"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kiterrors "github.com/crypto-zero/go-kit/errors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

type testUser struct{ ID int64 }

type testUserKey struct{}

type testSessionCache struct {
	userID int64
	err    error
}

func (c testSessionCache) GetUserIDBySessionID(context.Context, string, time.Duration) (int64, error) {
	return c.userID, c.err
}

type testUserProvider struct {
	user *testUser
	err  error
}

func (p testUserProvider) GetUserByID(context.Context, int64) (*testUser, error) {
	return p.user, p.err
}

func TestAuthMiddlewareInjectsUserForPrivateRoute(t *testing.T) {
	mux := runtime.NewServeMux(runtime.WithMiddlewares(Auth(AuthConfig[testUser]{
		Cache:    testSessionCache{userID: 42},
		Provider: testUserProvider{user: &testUser{ID: 42}},
		Policy: NewOperationPolicy(WithPublicHTTPRules(HTTPRule{
			Method:  http.MethodGet,
			Pattern: "/v1/public",
		})),
		NewUserContext: func(ctx context.Context, user *testUser) context.Context {
			return context.WithValue(ctx, testUserKey{}, user)
		},
	})))
	if err := mux.HandlePath(http.MethodGet, "/v1/private", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		user, ok := r.Context().Value(testUserKey{}).(*testUser)
		if !ok || user.ID != 42 {
			t.Fatalf("missing injected user: %#v", user)
		}
		w.WriteHeader(http.StatusNoContent)
	}); err != nil {
		t.Fatalf("HandlePath: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/private", nil)
	req.Header.Set(DefaultSessionHeader, "session")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestAuthMiddlewareSkipsPublicRoute(t *testing.T) {
	mux := runtime.NewServeMux(runtime.WithMiddlewares(Auth(AuthConfig[testUser]{
		Cache: testSessionCache{err: stderrors.New("should not be called")},
		Policy: NewOperationPolicy(WithPublicHTTPRules(HTTPRule{
			Method:  http.MethodGet,
			Pattern: "/v1/public",
		})),
	})))
	if err := mux.HandlePath(http.MethodGet, "/v1/public", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		w.WriteHeader(http.StatusNoContent)
	}); err != nil {
		t.Fatalf("HandlePath: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/public", nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	mux := runtime.NewServeMux(runtime.WithMiddlewares(Auth(AuthConfig[testUser]{
		Cache:          testSessionCache{userID: 42},
		Provider:       testUserProvider{user: &testUser{ID: 42}},
		NewUserContext: func(ctx context.Context, user *testUser) context.Context { return ctx },
	})))
	if err := mux.HandlePath(http.MethodGet, "/v1/private", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		w.WriteHeader(http.StatusNoContent)
	}); err != nil {
		t.Fatalf("HandlePath: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/private", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAuthMiddlewareUsesConfiguredUnauthenticatedError(t *testing.T) {
	mux := runtime.NewServeMux(runtime.WithMiddlewares(Auth(AuthConfig[testUser]{
		Cache:                testSessionCache{userID: 42},
		Provider:             testUserProvider{user: &testUser{ID: 42}},
		NewUserContext:       func(ctx context.Context, user *testUser) context.Context { return ctx },
		UnauthenticatedError: kiterrors.New(401, "PROJECT_INVALID_TOKEN", "project invalid token"),
	})))
	if err := mux.HandlePath(http.MethodGet, "/v1/private", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		w.WriteHeader(http.StatusNoContent)
	}); err != nil {
		t.Fatalf("HandlePath: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/private", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROJECT_INVALID_TOKEN") {
		t.Fatalf("body missing configured reason: %s", rec.Body.String())
	}
}
