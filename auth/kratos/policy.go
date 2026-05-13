// Package kratos provides auth helpers for Kratos operation selectors.
package kratos

import (
	authv1 "github.com/crypto-zero/go-kit/proto/kit/auth/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
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
	return "/" + string(m.Parent().FullName()) + "/" + string(m.Name())
}

func registerPublicFromFile(p *OperationPolicy, fd protoreflect.FileDescriptor) {
	services := fd.Services()
	for i := 0; i < services.Len(); i++ {
		methods := services.Get(i).Methods()
		for j := 0; j < methods.Len(); j++ {
			m := methods.Get(j)
			if methodIsPublic(m) {
				p.public[OperationName(m)] = struct{}{}
			}
		}
	}
}

func methodIsPublic(m protoreflect.MethodDescriptor) bool {
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil {
		return false
	}
	v := proto.GetExtension(opts, authv1.E_Public)
	switch public := v.(type) {
	case bool:
		return public || methodOptionsUnknownBool(opts, authv1.E_Public.TypeDescriptor().Number())
	case *bool:
		return (public != nil && *public) || methodOptionsUnknownBool(opts, authv1.E_Public.TypeDescriptor().Number())
	default:
		return methodOptionsUnknownBool(opts, authv1.E_Public.TypeDescriptor().Number())
	}
}

func methodOptionsUnknownBool(opts *descriptorpb.MethodOptions, number protoreflect.FieldNumber) bool {
	raw := opts.ProtoReflect().GetUnknown()
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return false
		}
		raw = raw[n:]
		if num != protowire.Number(number) {
			n = protowire.ConsumeFieldValue(num, typ, raw)
			if n < 0 {
				return false
			}
			raw = raw[n:]
			continue
		}
		if typ != protowire.VarintType {
			return false
		}
		v, n := protowire.ConsumeVarint(raw)
		return n >= 0 && v != 0
	}
	return false
}
