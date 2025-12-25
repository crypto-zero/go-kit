package main

import (
	"testing"

	"google.golang.org/protobuf/compiler/protogen"
)

func TestProtocVersion(t *testing.T) {
	tests := []struct {
		name    string
		version *protogen.Plugin
		want    string
	}{
		{
			name:    "nil_version",
			version: &protogen.Plugin{},
			want:    "(unknown)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocVersion(tt.version)
			if got != tt.want {
				t.Errorf("protocVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
