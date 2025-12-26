package main

import (
	"strings"
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

// =============================================================================
// needsFmtPackage Tests
// =============================================================================

func TestNeedsFmtPackage(t *testing.T) {
	tests := []struct {
		name     string
		messages []*messageDesc
		expected bool
	}{
		{
			name:     "empty messages",
			messages: []*messageDesc{},
			expected: false,
		},
		{
			name: "no map fields",
			messages: []*messageDesc{
				{
					Name: "User",
					Fields: []*fieldDesc{
						{GoName: "Name", IsMap: false, Redact: false},
						{GoName: "Email", IsMap: false, Redact: true},
					},
				},
			},
			expected: false,
		},
		{
			name: "redacted map field only",
			messages: []*messageDesc{
				{
					Name: "Config",
					Fields: []*fieldDesc{
						{GoName: "Settings", IsMap: true, Redact: true},
					},
				},
			},
			expected: false,
		},
		{
			name: "non-redacted map field",
			messages: []*messageDesc{
				{
					Name: "Config",
					Fields: []*fieldDesc{
						{GoName: "Settings", IsMap: true, Redact: false},
					},
				},
			},
			expected: true,
		},
		{
			name: "mixed fields with non-redacted map",
			messages: []*messageDesc{
				{
					Name: "User",
					Fields: []*fieldDesc{
						{GoName: "Name", IsMap: false, Redact: false},
						{GoName: "Email", IsMap: false, Redact: true},
					},
				},
				{
					Name: "Config",
					Fields: []*fieldDesc{
						{GoName: "RedactedMap", IsMap: true, Redact: true},
						{GoName: "PublicMap", IsMap: true, Redact: false},
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsFmtPackage(tt.messages); got != tt.expected {
				t.Errorf("needsFmtPackage() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Template Execution Tests
// =============================================================================

func TestMessageDescExecute(t *testing.T) {
	tests := []struct {
		name    string
		msg     *messageDesc
		wantErr bool
	}{
		{
			name: "simple message with string field",
			msg: &messageDesc{
				Name: "User",
				Fields: []*fieldDesc{
					{GoName: "Name", JSONName: "name", Redact: false},
					{GoName: "Email", JSONName: "email", Redact: true, StringMask: "*"},
				},
			},
			wantErr: false,
		},
		{
			name: "message with all field types",
			msg: &messageDesc{
				Name: "AllTypes",
				Fields: []*fieldDesc{
					{GoName: "StrField", JSONName: "strField", Redact: true, StringMask: "[HIDDEN]"},
					{GoName: "IntField", JSONName: "intField", Redact: true, IsInteger: true, IntMask: 0},
					{GoName: "FloatField", JSONName: "floatField", Redact: true, IsFloat: true, DoubleMask: 0},
					{GoName: "BoolField", JSONName: "boolField", Redact: true, IsBool: true, BoolMask: false},
					{GoName: "BytesField", JSONName: "bytesField", Redact: true, IsBytes: true, BytesMask: ""},
					{GoName: "EnumField", JSONName: "enumField", Redact: true, IsEnum: true, EnumMask: 0},
					{GoName: "MsgField", JSONName: "msgField", Redact: true, IsMessage: true},
					{GoName: "RepeatedField", JSONName: "repeatedField", Redact: true, IsRepeated: true},
					{GoName: "MapField", JSONName: "mapField", Redact: true, IsMap: true},
				},
			},
			wantErr: false,
		},
		{
			name: "message with oneof field",
			msg: &messageDesc{
				Name: "OneofMsg",
				Fields: []*fieldDesc{
					{GoName: "Value", JSONName: "value", IsOneof: true, IsMessage: true},
				},
			},
			wantErr: false,
		},
		{
			name: "message with map containing message values",
			msg: &messageDesc{
				Name: "MapMsg",
				Fields: []*fieldDesc{
					{GoName: "UserMap", JSONName: "userMap", IsMap: true, MapValueIsMessage: true},
				},
			},
			wantErr: false,
		},
		{
			name: "message with special characters in mask",
			msg: &messageDesc{
				Name: "SpecialMsg",
				Fields: []*fieldDesc{
					{GoName: "Password", JSONName: "password", Redact: true, StringMask: `"quoted"`},
					{GoName: "Token", JSONName: "token", Redact: true, StringMask: "line1\nline2"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.msg.execute()
			if result == "" {
				t.Error("execute() returned empty string")
			}

			// Basic sanity checks
			if !strings.Contains(result, "func (x *"+tt.msg.Name+") redact()") {
				t.Errorf("Missing redact() method signature")
			}
			if !strings.Contains(result, "func (x *"+tt.msg.Name+") Redact()") {
				t.Errorf("Missing Redact() method signature")
			}
		})
	}
}

func TestMessageDescExecute_EmptyMessage(t *testing.T) {
	msg := &messageDesc{
		Name:   "EmptyMessage",
		Fields: []*fieldDesc{},
	}

	result := msg.execute()
	if result == "" {
		t.Error("execute() should handle empty fields")
	}
}

// =============================================================================
// Default Values Tests
// =============================================================================

func TestDefaultStringMask(t *testing.T) {
	if defaultStringMask != "*" {
		t.Errorf("defaultStringMask = %q, want %q", defaultStringMask, "*")
	}
}

func TestFieldDescDefaults(t *testing.T) {
	fd := &fieldDesc{
		GoName:     "TestField",
		StringMask: defaultStringMask,
	}

	// Check Go zero values are used for other masks
	if fd.IntMask != 0 {
		t.Errorf("IntMask should default to 0, got %d", fd.IntMask)
	}
	if fd.DoubleMask != 0 {
		t.Errorf("DoubleMask should default to 0, got %f", fd.DoubleMask)
	}
	if fd.BoolMask != false {
		t.Errorf("BoolMask should default to false, got %v", fd.BoolMask)
	}
	if fd.BytesMask != "" {
		t.Errorf("BytesMask should default to empty, got %q", fd.BytesMask)
	}
	if fd.EnumMask != 0 {
		t.Errorf("EnumMask should default to 0, got %d", fd.EnumMask)
	}
}
