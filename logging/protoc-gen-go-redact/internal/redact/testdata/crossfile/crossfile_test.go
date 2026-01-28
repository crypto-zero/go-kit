package crossfile

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCrossFilePropagation_Container verifies that Container.Redact() correctly
// masks sensitive fields from the cross-file referenced SensitiveData message.
func TestCrossFilePropagation_Container(t *testing.T) {
	container := &Container{
		ContainerId: "container-123",
		Sensitive: &SensitiveData{
			Id:       "data-1",
			Password: "super-secret-password",
			Phone:    "+1-555-1234",
		},
	}

	result := container.Redact()
	t.Logf("Container.Redact(): %s", result)

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Redact() returned invalid JSON: %v", err)
	}

	// Verify containerId is NOT masked
	if parsed["containerId"] != "container-123" {
		t.Errorf("containerId should be visible, got: %v", parsed["containerId"])
	}

	// Verify sensitive fields ARE masked
	if strings.Contains(result, "super-secret-password") {
		t.Error("password should be masked but appears in output")
	}
	if strings.Contains(result, "+1-555-1234") {
		t.Error("phone should be masked but appears in output")
	}

	// Verify mask values are present
	if !strings.Contains(result, "[PASSWORD]") {
		t.Error("expected [PASSWORD] mask in output")
	}
	if !strings.Contains(result, "[PHONE]") {
		t.Error("expected [PHONE] mask in output")
	}
}

// TestCrossFilePropagation_ListContainer verifies repeated cross-file references work.
func TestCrossFilePropagation_ListContainer(t *testing.T) {
	listContainer := &ListContainer{
		Items: []*SensitiveData{
			{Id: "item-1", Password: "pw1", Phone: "111-1111"},
			{Id: "item-2", Password: "pw2", Phone: "222-2222"},
		},
	}

	result := listContainer.Redact()
	t.Logf("ListContainer.Redact(): %s", result)

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Redact() returned invalid JSON: %v", err)
	}

	// Verify passwords are masked
	if strings.Contains(result, "pw1") || strings.Contains(result, "pw2") {
		t.Error("passwords should be masked")
	}

	// Verify phones are masked
	if strings.Contains(result, "111-1111") || strings.Contains(result, "222-2222") {
		t.Error("phones should be masked")
	}

	// Verify IDs are visible (not redacted)
	if !strings.Contains(result, "item-1") || !strings.Contains(result, "item-2") {
		t.Error("item IDs should be visible")
	}
}

// TestCrossFilePropagation_DeepContainer verifies deep nested cross-file references work.
func TestCrossFilePropagation_DeepContainer(t *testing.T) {
	deepContainer := &DeepContainer{
		Id: "deep-container-1",
		Nested: &NestedSensitive{
			Name: "Nested Name",
			Data: &SensitiveData{
				Id:       "nested-data-1",
				Password: "deep-secret",
				Phone:    "333-3333",
			},
		},
	}

	result := deepContainer.Redact()
	t.Logf("DeepContainer.Redact(): %s", result)

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Redact() returned invalid JSON: %v", err)
	}

	// Verify the deeply nested sensitive fields are masked
	if strings.Contains(result, "deep-secret") {
		t.Error("deep nested password should be masked")
	}
	if strings.Contains(result, "333-3333") {
		t.Error("deep nested phone should be masked")
	}

	// Verify non-sensitive fields are visible
	if !strings.Contains(result, "deep-container-1") {
		t.Error("container ID should be visible")
	}
	if !strings.Contains(result, "Nested Name") {
		t.Error("nested name should be visible")
	}
}

// TestCrossFilePropagation_MapContainer verifies map with cross-file message values work.
func TestCrossFilePropagation_MapContainer(t *testing.T) {
	mapContainer := &MapContainer{
		DataMap: map[string]*SensitiveData{
			"key1": {Id: "map-data-1", Password: "map-pw-1", Phone: "444-4444"},
			"key2": {Id: "map-data-2", Password: "map-pw-2", Phone: "555-5555"},
		},
	}

	result := mapContainer.Redact()
	t.Logf("MapContainer.Redact(): %s", result)

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Redact() returned invalid JSON: %v", err)
	}

	// Verify passwords in map values are masked
	if strings.Contains(result, "map-pw-1") || strings.Contains(result, "map-pw-2") {
		t.Error("map value passwords should be masked")
	}

	// Verify phones in map values are masked
	if strings.Contains(result, "444-4444") || strings.Contains(result, "555-5555") {
		t.Error("map value phones should be masked")
	}

	// Verify map keys are visible
	if !strings.Contains(result, "key1") || !strings.Contains(result, "key2") {
		t.Error("map keys should be visible")
	}
}

// TestCrossFilePropagation_NilHandling verifies nil handling in cross-file scenarios.
func TestCrossFilePropagation_NilHandling(t *testing.T) {
	// Test nil container
	var nilContainer *Container
	result := nilContainer.Redact()
	if result != "{}" {
		t.Errorf("nil Container.Redact() should return {}, got: %s", result)
	}

	// Test container with nil sensitive field
	containerNilSensitive := &Container{
		ContainerId: "container-nil-sensitive",
		Sensitive:   nil,
	}
	result = containerNilSensitive.Redact()
	t.Logf("Container with nil Sensitive.Redact(): %s", result)
	if !strings.Contains(result, "container-nil-sensitive") {
		t.Error("container ID should be visible even when Sensitive is nil")
	}
}
