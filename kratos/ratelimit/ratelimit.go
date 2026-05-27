// Package ratelimit provides rate-limit middleware for Kratos services.
package ratelimit

import (
	"context"
	"strconv"
	"strings"

	"github.com/crypto-zero/go-kit/kratos/clientip"
	"github.com/crypto-zero/go-kit/ratelimit"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

const (
	defaultKey = "global"
	reason     = "RATELIMIT"
)

// ErrLimitExceed is returned when a request exceeds its rate limit.
var ErrLimitExceed = errors.New(429, reason, "service unavailable due to rate limit exceeded")

// Limiter is the behavior required by the middleware.
type Limiter interface {
	AllowContext(context.Context, string) (ratelimit.Result, error)
}

// KeyFunc derives a rate-limit key from a request.
type KeyFunc func(context.Context, any) string

// Option configures server middleware.
type Option func(*options)

type options struct {
	keyFunc KeyFunc
	err     *errors.Error
	policy  *OperationPolicy
}

// WithKeyFunc sets how requests are grouped into buckets.
func WithKeyFunc(fn KeyFunc) Option {
	return func(o *options) {
		if fn != nil {
			o.keyFunc = fn
		}
	}
}

// WithError sets the error returned when a request is rejected.
func WithError(err *errors.Error) Option {
	return func(o *options) {
		if err != nil {
			o.err = err
		}
	}
}

// WithOperationPolicy sets per-operation rate-limit rules.
func WithOperationPolicy(policy *OperationPolicy) Option {
	return func(o *options) {
		o.policy = policy
	}
}

// Server returns a Kratos server middleware using limiter.
func Server(limiter Limiter, opts ...Option) middleware.Middleware {
	if limiter == nil {
		limiter = ratelimit.NewDefault()
	}
	o := &options{
		keyFunc: OperationKey,
		err:     ErrLimitExceed,
	}
	for _, opt := range opts {
		opt(o)
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			activeLimiter := limiter
			keyFunc := o.keyFunc
			if opLimiter, opKeyFunc, ok := o.policy.lookup(OperationKey(ctx, req)); ok {
				activeLimiter = opLimiter
				keyFunc = opKeyFunc
			}
			key := keyFunc(ctx, req)
			res, err := activeLimiter.AllowContext(ctx, key)
			if err != nil {
				return nil, err
			}
			if !res.Allowed {
				return nil, o.err.WithMetadata(retryMetadata(res))
			}
			return handler(ctx, req)
		}
	}
}

// OperationKey groups requests by Kratos operation.
func OperationKey(ctx context.Context, _ any) string {
	if tr, ok := transport.FromServerContext(ctx); ok && tr.Operation() != "" {
		return tr.Operation()
	}
	return defaultKey
}

// ClientIPKey groups requests by client IP address.
func ClientIPKey(ctx context.Context, _ any) string {
	if ip := clientip.FromContext(ctx); ip != "" {
		return ip
	}
	return defaultKey
}

// CompositeKey joins multiple key functions into one key.
func CompositeKey(fns ...KeyFunc) KeyFunc {
	return func(ctx context.Context, req any) string {
		parts := make([]string, 0, len(fns))
		for _, fn := range fns {
			if fn == nil {
				continue
			}
			if part := fn(ctx, req); part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) == 0 {
			return defaultKey
		}
		return strings.Join(parts, ":")
	}
}

func retryMetadata(res ratelimit.Result) map[string]string {
	md := map[string]string{
		"remaining": strconv.Itoa(res.Remaining),
	}
	if res.RetryAfter > 0 {
		md["retry_after"] = strconv.FormatFloat(res.RetryAfter.Seconds(), 'f', 3, 64)
	}
	return md
}
