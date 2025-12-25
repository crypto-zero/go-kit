package main

import (
	"strings"
	"testing"
)

func TestRelease(t *testing.T) {
	if release == "" {
		t.Error("release version should not be empty")
	}

	if !strings.HasPrefix(release, "v") {
		t.Errorf("release version should start with 'v', got: %s", release)
	}

	// Check format: vX.Y.Z
	parts := strings.Split(strings.TrimPrefix(release, "v"), ".")
	if len(parts) < 3 {
		t.Errorf("release version should be in format vX.Y.Z, got: %s", release)
	}
}

