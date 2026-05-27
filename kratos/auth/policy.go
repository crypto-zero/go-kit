// Package auth provides auth helpers for Kratos operation selectors.
package auth

import (
	"github.com/crypto-zero/go-kit/kratos/internal/protoop"
	authv1 "github.com/crypto-zero/go-kit/proto/kit/auth/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// OperationPolicy reports whether a Kratos operation should run through
// authentication middleware.
type OperationPolicy struct {
	public map[string]struct{}
}

// OperationPolicyOption configures an OperationPolicy.
type OperationPolicyOption func(*OperationPolicy)

// NewOperationPolicy constructs an auth policy from proto descriptors and
// optional manually registered operations.
func NewOperationPolicy(opts ...OperationPolicyOption) *OperationPolicy {
	p := &OperationPolicy{public: make(map[string]struct{})}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithPublicOperations marks explicit Kratos operations as public.
func WithPublicOperations(ops ...string) OperationPolicyOption {
	return func(p *OperationPolicy) {
		for _, op := range ops {
			p.public[op] = struct{}{}
		}
	}
}

// WithPublicFromProtoFiles scans file descriptors for methods tagged with
// `(kit.auth.v1.public) = true`.
func WithPublicFromProtoFiles(files ...protoreflect.FileDescriptor) OperationPolicyOption {
	return func(p *OperationPolicy) {
		for _, fd := range files {
			registerPublicFromFile(p, fd)
		}
	}
}

// RequiresAuth reports whether operation should run through authentication.
func (p *OperationPolicy) RequiresAuth(operation string) bool {
	_, ok := p.public[operation]
	return !ok
}

// OperationName returns the Kratos operation string for a proto method.
func OperationName(m protoreflect.MethodDescriptor) string {
	return protoop.OperationName(m)
}

func registerPublicFromFile(p *OperationPolicy, fd protoreflect.FileDescriptor) {
	protoop.WalkMethods([]protoreflect.FileDescriptor{fd}, func(m protoreflect.MethodDescriptor) {
		if methodIsPublic(m) {
			p.public[protoop.OperationName(m)] = struct{}{}
		}
	})
}

func methodIsPublic(m protoreflect.MethodDescriptor) bool {
	return protoop.BoolExtension(m, authv1.E_Public)
}
