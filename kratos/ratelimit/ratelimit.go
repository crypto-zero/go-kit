// Package ratelimit provides rate-limit middleware for Kratos services.
package ratelimit

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/crypto-zero/go-kit/kratos/clientip"
	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

// Reason is the Kratos error reason emitted when a request is rejected.
const Reason = "RATELIMIT"

// Metadata keys carried on the Kratos error returned by Server.
const (
	MetadataRemaining  = "remaining"
	MetadataRetryAfter = "retry_after"
)

// ErrLimitExceed is returned when a request exceeds its rate limit.
var ErrLimitExceed = kratoserrors.New(429, Reason, "service unavailable due to rate limit exceeded")

// ErrStoreUnavailable is returned when the backing store cannot evaluate a
// limit decision.
var ErrStoreUnavailable = kratoserrors.New(503, "RATELIMIT_UNAVAILABLE", "service unavailable due to rate limit store unavailable")

// ErrPolicyConflict reports that incompatible options were combined — most
// commonly passing both WithOperationPolicy and one of WithOperationRules,
// WithRuleStore, WithUserKeyFunc, or WithClientIPKeyFunc.
var ErrPolicyConflict = errors.New("ratelimit: WithOperationPolicy conflicts with rule-building options")

// ErrMissingRules reports rule-building options that do not include any
// operation rules.
var ErrMissingRules = errors.New("ratelimit: missing operation rules")

// KeyFunc derives a rate-limit key from a request.
type KeyFunc func(context.Context, any) string

// Option configures Server.
type Option func(*options)

type options struct {
	err             *kratoserrors.Error
	policy          *OperationPolicy
	store           Store
	rules           OperationRules
	clientIPKeyFunc KeyFunc
	userKeyFunc     KeyFunc
	storeSet        bool
	rulesSet        bool
	clientIPSet     bool
	userSet         bool
}

// WithRuleStore sets the storage backend used to build operation rules.
func WithRuleStore(store Store) Option {
	return func(o *options) {
		o.store = store
		o.storeSet = true
	}
}

// WithError sets the error returned when a request is rejected.
func WithError(err *kratoserrors.Error) Option {
	return func(o *options) {
		if err != nil {
			o.err = err
		}
	}
}

// WithOperationPolicy installs a pre-built policy. Mutually exclusive with
// WithOperationRules / WithRuleStore / WithUserKeyFunc / WithClientIPKeyFunc.
func WithOperationPolicy(policy *OperationPolicy) Option {
	return func(o *options) { o.policy = policy }
}

// WithOperationRules sets per-operation rate-limit rules from external config.
func WithOperationRules(rules OperationRules) Option {
	return func(o *options) {
		o.rules = rules
		o.rulesSet = true
	}
}

// WithUserKeyFunc sets how user_id key parts are extracted from requests.
func WithUserKeyFunc(fn KeyFunc) Option {
	return func(o *options) {
		o.userKeyFunc = fn
		o.userSet = true
	}
}

// WithClientIPKeyFunc sets how client_ip key parts are extracted from requests.
func WithClientIPKeyFunc(fn KeyFunc) Option {
	return func(o *options) {
		o.clientIPKeyFunc = fn
		o.clientIPSet = true
	}
}

// Server returns a Kratos server middleware that enforces rate limits.
//
// Construction errors are returned eagerly so callers fail-fast at startup
// instead of crashing on the first request. HTTP handlers must set a Kratos
// operation with http.SetOperation; requests without an operation are treated
// as unconfigured and are not limited.
func Server(opts ...Option) (middleware.Middleware, error) {
	o := &options{err: ErrLimitExceed}
	for _, opt := range opts {
		opt(o)
	}
	if o.policy != nil {
		if o.rulesSet || o.storeSet || o.userSet || o.clientIPSet {
			return nil, ErrPolicyConflict
		}
		if err := o.policy.validate(); err != nil {
			return nil, err
		}
	} else if o.rulesSet {
		if len(o.rules) == 0 {
			return nil, ErrMissingRules
		}
		policy, err := NewOperationPolicy(o.store, o.rules,
			WithPolicyClientIPKeyFunc(o.clientIPKeyFunc),
			WithPolicyUserKeyFunc(o.userKeyFunc),
		)
		if err != nil {
			return nil, err
		}
		o.policy = policy
	} else {
		return nil, ErrMissingRules
	}
	policy := o.policy
	errResp := o.err
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			results, err := policy.allow(ctx, OperationKey(ctx, req), req)
			if err != nil {
				if errors.Is(err, ErrMissingKey) {
					return nil, errResp.WithMetadata(map[string]string{
						MetadataRemaining: "0",
					}).WithCause(err)
				}
				return nil, ErrStoreUnavailable.WithCause(err)
			}
			if rejected, ok := rejectedResult(results); ok {
				return nil, errResp.WithMetadata(retryMetadata(rejected))
			}
			return handler(ctx, req)
		}
	}, nil
}

func rejectedResult(results []Result) (Result, bool) {
	var rejected Result
	var ok bool
	for _, res := range results {
		if !res.Allowed && (!ok || res.RetryAfter > rejected.RetryAfter) {
			rejected = res
			ok = true
		}
	}
	return rejected, ok
}

// OperationKey returns the Kratos operation from the server context.
func OperationKey(ctx context.Context, _ any) string {
	if tr, ok := transport.FromServerContext(ctx); ok {
		return tr.Operation()
	}
	return ""
}

// ClientIPKey returns the client IP from the server context.
func ClientIPKey(ctx context.Context, _ any) string {
	return clientip.FromContext(ctx)
}

// CompositeKey joins multiple key functions into one. If any underlying
// function returns the empty string, the composite returns the empty string —
// callers can distinguish "key fully derived" from "at least one dimension
// missing" without silently collapsing into a narrower bucket.
func CompositeKey(fns ...KeyFunc) KeyFunc {
	return func(ctx context.Context, req any) string {
		parts := make([]string, 0, len(fns))
		for _, fn := range fns {
			if fn == nil {
				continue
			}
			part := fn(ctx, req)
			if part == "" {
				return ""
			}
			parts = append(parts, part)
		}
		return strings.Join(parts, ":")
	}
}

func operationScopedKey(operation string, fn KeyFunc) KeyFunc {
	return func(ctx context.Context, req any) string {
		if fn == nil {
			return operation
		}
		key := fn(ctx, req)
		if key == "" {
			return ""
		}
		return operation + ":" + key
	}
}

func retryMetadata(res Result) map[string]string {
	md := map[string]string{
		MetadataRemaining: strconv.Itoa(res.Remaining),
	}
	if res.RetryAfter > 0 {
		md[MetadataRetryAfter] = strconv.FormatFloat(res.RetryAfter.Seconds(), 'f', 3, 64)
	}
	return md
}
