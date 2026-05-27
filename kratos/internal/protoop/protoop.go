// Package protoop contains helpers for Kratos proto operation descriptors.
package protoop

import (
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// WalkMethods calls fn for every method in files.
func WalkMethods(files []protoreflect.FileDescriptor, fn func(protoreflect.MethodDescriptor)) {
	for _, fd := range files {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			methods := services.Get(i).Methods()
			for j := 0; j < methods.Len(); j++ {
				fn(methods.Get(j))
			}
		}
	}
}

// OperationName returns the Kratos operation string for a proto method.
func OperationName(m protoreflect.MethodDescriptor) string {
	return "/" + string(m.Parent().FullName()) + "/" + string(m.Name())
}

// Extension returns the extension value from a proto method option.
func Extension(m protoreflect.MethodDescriptor, ext protoreflect.ExtensionType) (any, bool) {
	opts, ok := m.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil {
		return nil, false
	}
	return proto.GetExtension(opts, ext), true
}

// BoolExtension reports whether a boolean extension is set to true.
func BoolExtension(m protoreflect.MethodDescriptor, ext protoreflect.ExtensionType) bool {
	v, ok := Extension(m, ext)
	if !ok {
		return false
	}
	opts := m.Options().(*descriptorpb.MethodOptions)
	number := ext.TypeDescriptor().Number()
	switch value := v.(type) {
	case bool:
		return value || unknownBool(opts, number)
	case *bool:
		return (value != nil && *value) || unknownBool(opts, number)
	default:
		return unknownBool(opts, number)
	}
}

func unknownBool(opts *descriptorpb.MethodOptions, number protoreflect.FieldNumber) bool {
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
