package main

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// =============================================================================
// Type Detection Tests
// =============================================================================

func TestIntegerKinds(t *testing.T) {
	tests := []struct {
		kind     protoreflect.Kind
		expected bool
	}{
		{protoreflect.Int32Kind, true},
		{protoreflect.Int64Kind, true},
		{protoreflect.Uint32Kind, true},
		{protoreflect.Uint64Kind, true},
		{protoreflect.Sint32Kind, true},
		{protoreflect.Sint64Kind, true},
		{protoreflect.Fixed32Kind, true},
		{protoreflect.Fixed64Kind, true},
		{protoreflect.Sfixed32Kind, true},
		{protoreflect.Sfixed64Kind, true},
		// Non-integer types
		{protoreflect.FloatKind, false},
		{protoreflect.DoubleKind, false},
		{protoreflect.StringKind, false},
		{protoreflect.BoolKind, false},
		{protoreflect.BytesKind, false},
		{protoreflect.MessageKind, false},
		{protoreflect.EnumKind, false},
	}

	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			if got := integerKinds[tt.kind]; got != tt.expected {
				t.Errorf("integerKinds[%s] = %v, want %v", tt.kind, got, tt.expected)
			}
		})
	}
}

func TestFloatKinds(t *testing.T) {
	tests := []struct {
		kind     protoreflect.Kind
		expected bool
	}{
		{protoreflect.FloatKind, true},
		{protoreflect.DoubleKind, true},
		// Non-float types
		{protoreflect.Int32Kind, false},
		{protoreflect.Int64Kind, false},
		{protoreflect.StringKind, false},
		{protoreflect.BoolKind, false},
	}

	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			if got := floatKinds[tt.kind]; got != tt.expected {
				t.Errorf("floatKinds[%s] = %v, want %v", tt.kind, got, tt.expected)
			}
		})
	}
}
