// Package auth provides auth helpers for Kratos operation selectors.
package auth

import (
	kitauth "github.com/crypto-zero/go-kit/auth"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// OperationPolicy reports whether a Kratos operation should run through
// authentication middleware.
type OperationPolicy = kitauth.OperationPolicy

// OperationPolicyOption configures an OperationPolicy.
type OperationPolicyOption = kitauth.OperationPolicyOption

// NewOperationPolicy constructs an auth policy from proto descriptors and
// optional manually registered operations.
func NewOperationPolicy(opts ...OperationPolicyOption) *OperationPolicy {
	return kitauth.NewOperationPolicy(opts...)
}

// WithPublicOperations marks explicit Kratos operations as public.
func WithPublicOperations(ops ...string) OperationPolicyOption {
	return kitauth.WithPublicOperations(ops...)
}

// WithPublicFromProtoFiles scans file descriptors for methods tagged with
// `(kit.auth.v1.public) = true`.
func WithPublicFromProtoFiles(files ...protoreflect.FileDescriptor) OperationPolicyOption {
	return kitauth.WithPublicFromProtoFiles(files...)
}

// OperationName returns the Kratos operation string for a proto method.
func OperationName(m protoreflect.MethodDescriptor) string {
	return kitauth.OperationName(m)
}
