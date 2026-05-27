package ratelimit

import (
	"time"

	"github.com/crypto-zero/go-kit/kratos/internal/protoop"
	ratelimitv1 "github.com/crypto-zero/go-kit/proto/kit/ratelimit/v1"
	coreratelimit "github.com/crypto-zero/go-kit/ratelimit"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// OperationPolicy selects rate-limit behavior for Kratos operations.
type OperationPolicy struct {
	operations map[string]operationLimit
	store      coreratelimit.Store
}

type operationLimit struct {
	limiter Limiter
	keyFunc KeyFunc
	config  coreratelimit.Config
}

// OperationPolicyOption configures an OperationPolicy.
type OperationPolicyOption func(*OperationPolicy)

// NewOperationPolicy constructs a policy from proto descriptors and manual
// operation rules.
func NewOperationPolicy(opts ...OperationPolicyOption) *OperationPolicy {
	p := &OperationPolicy{operations: make(map[string]operationLimit)}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithStore sets the storage backend used by operation-specific limiters.
func WithStore(store coreratelimit.Store) OperationPolicyOption {
	return func(p *OperationPolicy) {
		if store != nil {
			p.store = store
			for operation, rule := range p.operations {
				p.operations[operation] = p.build(rule.config, rule.keyFunc)
			}
		}
	}
}

// WithOperation registers a rate limit for one Kratos operation.
func WithOperation(operation string, cfg coreratelimit.Config, keyFunc KeyFunc) OperationPolicyOption {
	return func(p *OperationPolicy) {
		p.register(operation, cfg, keyFunc)
	}
}

// WithRateLimitFromProtoFiles scans file descriptors for methods tagged with
// `(kit.ratelimit.v1.rate_limit)`.
func WithRateLimitFromProtoFiles(files ...protoreflect.FileDescriptor) OperationPolicyOption {
	return func(p *OperationPolicy) {
		for _, fd := range files {
			registerRateLimitsFromFile(p, fd)
		}
	}
}

func (p *OperationPolicy) lookup(operation string) (Limiter, KeyFunc, bool) {
	if p == nil {
		return nil, nil, false
	}
	rule, ok := p.operations[operation]
	if !ok {
		return nil, nil, false
	}
	return rule.limiter, rule.keyFunc, true
}

func (p *OperationPolicy) register(operation string, cfg coreratelimit.Config, keyFunc KeyFunc) {
	if operation == "" || keyFunc == nil {
		return
	}
	rule := p.build(cfg, keyFunc)
	if rule.limiter == nil {
		return
	}
	p.operations[operation] = rule
}

func (p *OperationPolicy) build(cfg coreratelimit.Config, keyFunc KeyFunc) operationLimit {
	opts := []coreratelimit.Option(nil)
	if p.store != nil {
		opts = append(opts, coreratelimit.WithStore(p.store))
	}
	limiter, err := coreratelimit.New(cfg, opts...)
	if err != nil {
		return operationLimit{}
	}
	return operationLimit{
		limiter: limiter,
		keyFunc: keyFunc,
		config:  cfg,
	}
}

func registerRateLimitsFromFile(p *OperationPolicy, fd protoreflect.FileDescriptor) {
	protoop.WalkMethods([]protoreflect.FileDescriptor{fd}, func(m protoreflect.MethodDescriptor) {
		rule, ok := methodRateLimit(m)
		if !ok {
			return
		}
		p.register(protoop.OperationName(m), configFromProto(rule), keyFuncFromProto(rule.GetKey()))
	})
}

func methodRateLimit(m protoreflect.MethodDescriptor) (*ratelimitv1.RateLimit, bool) {
	v, ok := protoop.Extension(m, ratelimitv1.E_RateLimit)
	if !ok {
		return nil, false
	}
	rule, ok := v.(*ratelimitv1.RateLimit)
	return rule, ok && rule != nil
}

func configFromProto(rule *ratelimitv1.RateLimit) coreratelimit.Config {
	return coreratelimit.Config{
		Rate:  int(rule.GetRate()),
		Per:   durationFromProto(rule),
		Burst: int(rule.GetBurst()),
	}
}

func durationFromProto(rule *ratelimitv1.RateLimit) time.Duration {
	if rule.GetPer() == nil {
		return 0
	}
	return rule.GetPer().AsDuration()
}

func keyFuncFromProto(key ratelimitv1.Key) KeyFunc {
	switch key {
	case ratelimitv1.Key_KEY_CLIENT_IP:
		return ClientIPKey
	case ratelimitv1.Key_KEY_OPERATION_CLIENT_IP:
		return CompositeKey(OperationKey, ClientIPKey)
	default:
		return OperationKey
	}
}
