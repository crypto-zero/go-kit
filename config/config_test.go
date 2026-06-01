package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	_ "google.golang.org/protobuf/types/known/durationpb"
)

func TestUnmarshalYAMLScansProtoMessage(t *testing.T) {
	msg := newTestConfigMessage(t)

	if err := UnmarshalYAML([]byte(`
name: api
session_ttl: 5s
max_open_conns: 12
`), msg, Options{}); err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}

	fields := msg.Descriptor().Fields()
	if got := msg.Get(fields.ByName("name")).String(); got != "api" {
		t.Fatalf("name = %q, want api", got)
	}
	if got := msg.Get(fields.ByName("max_open_conns")).Int(); got != 12 {
		t.Fatalf("max_open_conns = %d, want 12", got)
	}
	duration := msg.Get(fields.ByName("session_ttl")).Message()
	if got := duration.Get(duration.Descriptor().Fields().ByName("seconds")).Int(); got != 5 {
		t.Fatalf("session_ttl.seconds = %d, want 5", got)
	}
}

func TestUnmarshalYAMLRejectsUnknownFieldsByDefault(t *testing.T) {
	msg := newTestConfigMessage(t)

	err := UnmarshalYAML([]byte("unknown_root: true\n"), msg, Options{})
	if err == nil {
		t.Fatal("UnmarshalYAML error = nil, want unknown field error")
	}
	if !strings.Contains(err.Error(), "unknown_root") {
		t.Fatalf("UnmarshalYAML error = %v, want unknown_root", err)
	}
}

func TestUnmarshalYAMLCanDiscardUnknownFields(t *testing.T) {
	msg := newTestConfigMessage(t)

	if err := UnmarshalYAML([]byte("unknown_root: true\n"), msg, Options{DiscardUnknown: true}); err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
}

func TestLoadYAMLFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("name: api\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	msg := newTestConfigMessage(t)

	if err := LoadYAMLFile(path, msg); err != nil {
		t.Fatalf("LoadYAMLFile: %v", err)
	}
	if got := msg.Get(msg.Descriptor().Fields().ByName("name")).String(); got != "api" {
		t.Fatalf("name = %q, want api", got)
	}
}

func newTestConfigMessage(t *testing.T) *dynamicpb.Message {
	t.Helper()
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:     protoString("proto3"),
		Name:       protoString("config_test.proto"),
		Package:    protoString("kit.configtest"),
		Dependency: []string{"google/protobuf/duration.proto"},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: protoString("Config"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     protoString("name"),
						JsonName: protoString("name"),
						Number:   protoInt32(1),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					},
					{
						Name:     protoString("session_ttl"),
						JsonName: protoString("sessionTtl"),
						Number:   protoInt32(2),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: protoString(".google.protobuf.Duration"),
					},
					{
						Name:     protoString("max_open_conns"),
						JsonName: protoString("maxOpenConns"),
						Number:   protoInt32(3),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
					},
				},
			},
		},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	return dynamicpb.NewMessage(fd.Messages().ByName(protoreflect.Name("Config")))
}

func protoString(v string) *string { return &v }

func protoInt32(v int32) *int32 { return &v }
