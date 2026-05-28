package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// KeyPart identifies one business dimension used to build a rate-limit key.
type KeyPart string

const (
	KeyPartClientIP KeyPart = "client_ip"
	KeyPartUserID   KeyPart = "user_id"
)

// ParseKeyPart converts a canonical key-part name into a KeyPart. Callers that
// load rules from external config can use it to avoid re-implementing the
// allow-list of supported dimensions.
func ParseKeyPart(s string) (KeyPart, error) {
	switch KeyPart(s) {
	case KeyPartClientIP, KeyPartUserID:
		return KeyPart(s), nil
	default:
		return "", fmt.Errorf("unsupported key part %q", s)
	}
}

// RuleConfig provides the runtime limit for one operation rule.
type RuleConfig struct {
	Config   Config
	KeyParts []KeyPart
}

// OperationRules maps Kratos operation names to their runtime limit rules.
type OperationRules map[string][]RuleConfig

// OperationPolicy selects rate-limit behavior for Kratos operations.
type OperationPolicy struct {
	operations      map[string][]operationLimit
	store           Store
	now             func() time.Time
	clientIPKeyFunc KeyFunc
	userKeyFunc     KeyFunc
}

type operationLimit struct {
	keyFunc KeyFunc
	limit   Limit
}

// OperationPolicyOption configures an OperationPolicy.
type OperationPolicyOption func(*OperationPolicy)

// WithPolicyUserKeyFunc sets how operation policies extract the business user id.
func WithPolicyUserKeyFunc(fn KeyFunc) OperationPolicyOption {
	return func(p *OperationPolicy) {
		p.userKeyFunc = fn
	}
}

// WithPolicyClientIPKeyFunc sets how operation policies extract the client IP.
func WithPolicyClientIPKeyFunc(fn KeyFunc) OperationPolicyOption {
	return func(p *OperationPolicy) {
		p.clientIPKeyFunc = fn
	}
}

// WithPolicyNow overrides the clock used to stamp Store calls. Mostly useful in tests.
func WithPolicyNow(now func() time.Time) OperationPolicyOption {
	return func(p *OperationPolicy) {
		if now != nil {
			p.now = now
		}
	}
}

// NewOperationPolicy constructs a policy from operation rules. All construction
// errors are returned eagerly; the resulting policy never silently disables
// limiting at runtime.
func NewOperationPolicy(
	store Store,
	rules OperationRules,
	opts ...OperationPolicyOption,
) (*OperationPolicy, error) {
	if store == nil {
		return nil, ErrMissingStore
	}
	if len(rules) == 0 {
		return nil, ErrMissingRules
	}
	p := &OperationPolicy{
		operations: make(map[string][]operationLimit, len(rules)),
		store:      store,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(p)
	}
	for operation, configs := range rules {
		if operation == "" {
			return nil, fmt.Errorf("ratelimit operation must not be empty")
		}
		if len(configs) == 0 {
			return nil, fmt.Errorf("%s: ratelimit rules must not be empty", operation)
		}
		seen := make(map[string]struct{}, len(configs))
		for _, cfg := range configs {
			sig := keyPartsSignature(cfg.KeyParts)
			label := ruleLabel(operation, sig)
			if err := validateKeyParts(cfg.KeyParts); err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
			if err := cfg.Config.Validate(); err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
			if _, dup := seen[sig]; dup {
				return nil, fmt.Errorf("%s: duplicate ratelimit rule %s", operation, sig)
			}
			seen[sig] = struct{}{}

			keyFunc, err := p.keyFuncFromParts(operation, cfg.KeyParts)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", operation, err)
			}
			p.operations[operation] = append(p.operations[operation], operationLimit{
				keyFunc: keyFunc,
				limit:   cfg.Config,
			})
		}
	}
	return p, nil
}

// allow runs every rule for operation in one atomic Store call and returns the
// per-rule Results. It returns (nil, nil) when no rule matches.
func (p *OperationPolicy) allow(ctx context.Context, operation string, req any) ([]Result, error) {
	if p == nil {
		return nil, nil
	}
	rules := p.operations[operation]
	if len(rules) == 0 {
		return nil, nil
	}
	keys := make([]string, len(rules))
	limits := make([]Limit, len(rules))
	for i, rule := range rules {
		key := rule.keyFunc(ctx, req)
		if key == "" {
			return nil, ErrMissingKey
		}
		keys[i] = key
		limits[i] = rule.limit
	}
	return p.store.TakeMany(ctx, keys, p.now(), limits, 1)
}

func (p *OperationPolicy) validate() error {
	// NewOperationPolicy already performs full validation. This method catches
	// zero-value policies passed through WithOperationPolicy.
	if p == nil || p.store == nil || len(p.operations) == 0 {
		return ErrMissingRules
	}
	return nil
}

func (p *OperationPolicy) keyFuncFromParts(operation string, parts []KeyPart) (KeyFunc, error) {
	fns := make([]KeyFunc, 0, len(parts))
	for _, part := range parts {
		fn, err := p.keyFuncForPart(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyPartsSignature(parts), err)
		}
		fns = append(fns, namedKeyPart(part, fn))
	}
	return operationScopedKey(operation, CompositeKey(fns...)), nil
}

func (p *OperationPolicy) keyFuncForPart(part KeyPart) (KeyFunc, error) {
	switch part {
	case KeyPartClientIP:
		if p.clientIPKeyFunc == nil {
			return nil, fmt.Errorf("client IP key function is required")
		}
		return p.clientIPKeyFunc, nil
	case KeyPartUserID:
		if p.userKeyFunc == nil {
			return nil, fmt.Errorf("user key function is required")
		}
		return p.userKeyFunc, nil
	default:
		return nil, fmt.Errorf("unsupported key part %s", part)
	}
}

func namedKeyPart(part KeyPart, fn KeyFunc) KeyFunc {
	return func(ctx context.Context, req any) string {
		value := fn(ctx, req)
		if value == "" {
			return ""
		}
		return string(part) + ":" + escapeKeyPartValue(value)
	}
}

var keyPartEscaper = strings.NewReplacer("%", "%25", ":", "%3A")

func escapeKeyPartValue(value string) string {
	return keyPartEscaper.Replace(value)
}

func validateKeyParts(parts []KeyPart) error {
	if len(parts) == 0 {
		return fmt.Errorf("key_parts must not be empty")
	}
	for _, part := range parts {
		switch part {
		case KeyPartClientIP, KeyPartUserID:
		default:
			return fmt.Errorf("unsupported key part %s", part)
		}
	}
	return nil
}

func keyPartsSignature(parts []KeyPart) string {
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		names = append(names, string(part))
	}
	return strings.Join(names, "+")
}

func ruleLabel(operation, sig string) string {
	if sig == "" {
		return operation
	}
	return operation + " " + sig
}
