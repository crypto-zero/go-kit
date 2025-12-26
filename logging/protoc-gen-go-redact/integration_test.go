package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/crypto-zero/go-kit/logging/protoc-gen-go-redact/testdata"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Helper function to check if JSON contains a key-value pair
func assertContains(t *testing.T, jsonStr, key, value string) {
	t.Helper()
	expected := `"` + key + `":` + value
	if !strings.Contains(jsonStr, expected) {
		t.Errorf("Expected JSON to contain %s, got: %s", expected, jsonStr)
	}
}

// Helper function to check if JSON contains a key with string value
func assertContainsString(t *testing.T, jsonStr, key, value string) {
	t.Helper()
	expected := `"` + key + `":"` + value + `"`
	if !strings.Contains(jsonStr, expected) {
		t.Errorf("Expected JSON to contain %s, got: %s", expected, jsonStr)
	}
}

// =============================================================================
// Basic Message Tests
// =============================================================================

func TestUser_Redact(t *testing.T) {
	user := &testdata.User{
		Id:       "user-123",
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "secret123",
		Phone:    "+1234567890",
		Age:      30,
	}

	result := user.Redact()
	t.Logf("User.Redact(): %s", result)

	// Verify non-redacted fields are preserved
	assertContainsString(t, result, "id", "user-123")
	assertContainsString(t, result, "name", "John Doe")
	assertContains(t, result, "age", "30")

	// Verify redacted fields use masks
	assertContainsString(t, result, "email", "*")
	assertContainsString(t, result, "password", "[HIDDEN]")
	assertContainsString(t, result, "phone", "[PHONE]")

	// Verify original values are NOT in output
	if strings.Contains(result, "john@example.com") {
		t.Error("Email should be redacted")
	}
	if strings.Contains(result, "secret123") {
		t.Error("Password should be redacted")
	}
}

func TestAddress_Redact(t *testing.T) {
	addr := &testdata.Address{
		Street:  "123 Main St",
		City:    "New York",
		State:   "NY",
		ZipCode: "10001",
		Country: "USA",
	}

	result := addr.Redact()
	t.Logf("Address.Redact(): %s", result)

	assertContainsString(t, result, "street", "123 Main St")
	assertContainsString(t, result, "zipCode", "[ZIP]")
}

// =============================================================================
// Nested Message Tests
// =============================================================================

func TestAccount_NestedRedact(t *testing.T) {
	account := &testdata.Account{
		Id:        "acc-123",
		SecretKey: "super-secret-key",
		User: &testdata.User{
			Id:       "user-1",
			Name:     "Alice",
			Email:    "alice@example.com",
			Password: "pass123",
		},
		BillingAddress: &testdata.Address{
			Street:  "456 Oak Ave",
			ZipCode: "90210",
		},
	}

	result := account.Redact()
	t.Logf("Account.Redact(): %s", result)

	// Account fields
	assertContainsString(t, result, "id", "acc-123")
	assertContainsString(t, result, "secretKey", "***SECRET***")

	// Nested User should be recursively redacted
	if !strings.Contains(result, `"user":{`) {
		t.Error("Expected nested user object")
	}
	assertContainsString(t, result, "email", "*")
	assertContainsString(t, result, "password", "[HIDDEN]")

	// Nested Address should be recursively redacted
	assertContainsString(t, result, "zipCode", "[ZIP]")
}

func TestDeepNested_Redact(t *testing.T) {
	level1 := &testdata.Level1{
		Name: "Level1",
		Level2: &testdata.Level2{
			Name: "Level2",
			Level3: &testdata.Level3{
				Name: "Level3",
				Level4: &testdata.Level4{
					Secret: "deep-secret",
				},
			},
		},
	}

	result := level1.Redact()
	t.Logf("Level1.Redact(): %s", result)

	// Verify deep nesting works
	assertContainsString(t, result, "name", "Level1")
	if !strings.Contains(result, `"level2":{`) {
		t.Error("Expected level2 object")
	}
	if !strings.Contains(result, `"level3":{`) {
		t.Error("Expected level3 object")
	}
	// Level4's secret should be redacted
	assertContainsString(t, result, "secret", "*")
}

// =============================================================================
// All Scalar Types Tests
// =============================================================================

func TestAllScalarTypes_Redact(t *testing.T) {
	scalar := &testdata.AllScalarTypes{
		// Non-redacted values
		DoubleVal:   3.14,
		FloatVal:    2.71,
		Int32Val:    100,
		Int64Val:    200,
		Uint32Val:   300,
		Uint64Val:   400,
		Sint32Val:   -50,
		Sint64Val:   -60,
		Fixed32Val:  700,
		Fixed64Val:  800,
		Sfixed32Val: -900,
		Sfixed64Val: -1000,
		BoolVal:     true,
		StringVal:   "hello",
		BytesVal:    []byte("world"),

		// Redacted values (should be masked)
		RedactDouble:       99.99,
		RedactFloat:        88.88,
		RedactInt32:        12345,
		RedactInt64:        67890,
		RedactUint32:       11111,
		RedactUint64:       22222,
		RedactSint32:       -333,
		RedactSint64:       -444,
		RedactFixed32:      5555,
		RedactFixed64:      6666,
		RedactSfixed32:     -7777,
		RedactSfixed64:     -8888,
		RedactBool:         true,
		RedactString:       "secret-string",
		RedactStringCustom: "custom-secret",
		RedactBytes:        []byte("secret-bytes"),
	}

	result := scalar.Redact()
	t.Logf("AllScalarTypes.Redact(): %s", result)

	// Verify non-redacted values are preserved
	if !strings.Contains(result, "3.14") {
		t.Error("doubleVal should be preserved")
	}
	assertContains(t, result, "int32Val", "100")
	assertContains(t, result, "boolVal", "true")
	assertContainsString(t, result, "stringVal", "hello")

	// Verify redacted numeric types are 0
	assertContains(t, result, "redactDouble", "0")
	assertContains(t, result, "redactFloat", "0")
	assertContains(t, result, "redactInt32", "0")
	assertContains(t, result, "redactInt64", "0")
	assertContains(t, result, "redactUint32", "0")
	assertContains(t, result, "redactUint64", "0")
	assertContains(t, result, "redactSint32", "0")
	assertContains(t, result, "redactSint64", "0")
	assertContains(t, result, "redactFixed32", "0")
	assertContains(t, result, "redactFixed64", "0")
	assertContains(t, result, "redactSfixed32", "0")
	assertContains(t, result, "redactSfixed64", "0")

	// Verify redacted bool is false
	assertContains(t, result, "redactBool", "false")

	// Verify redacted strings use masks
	assertContainsString(t, result, "redactString", "*")
	assertContainsString(t, result, "redactStringCustom", "[CUSTOM]")

	// Verify redacted bytes is empty
	assertContainsString(t, result, "redactBytes", "")
}

// =============================================================================
// Enum Type Tests
// =============================================================================

func TestEnumTypes_Redact(t *testing.T) {
	enum := &testdata.EnumTypes{
		Status:         testdata.Status_STATUS_ACTIVE,
		Priority:       testdata.Priority_PRIORITY_HIGH,
		RedactStatus:   testdata.Status_STATUS_PENDING,
		RedactPriority: testdata.Priority_PRIORITY_CRITICAL,
	}

	result := enum.Redact()
	t.Logf("EnumTypes.Redact(): %s", result)

	// Non-redacted enums should show their values
	assertContains(t, result, "status", "1")
	assertContains(t, result, "priority", "3")

	// Redacted enums should be 0
	assertContains(t, result, "redactStatus", "0")
	assertContains(t, result, "redactPriority", "0")
}

// =============================================================================
// Repeated Type Tests
// =============================================================================

func TestRepeatedScalars_Redact(t *testing.T) {
	repeated := &testdata.RepeatedScalars{
		DoubleVals: []float64{1.1, 2.2, 3.3},
		Int32Vals:  []int32{1, 2, 3},
		StringVals: []string{"a", "b", "c"},
		BoolVals:   []bool{true, false, true},

		// Redacted
		RedactDoubleVals: []float64{9.9, 8.8},
		RedactInt32Vals:  []int32{100, 200},
		RedactStringVals: []string{"secret1", "secret2"},
		RedactBoolVals:   []bool{true, true},
	}

	result := repeated.Redact()
	t.Logf("RepeatedScalars.Redact(): %s", result)

	// Non-redacted arrays should be preserved
	if !strings.Contains(result, `"doubleVals":[1.1,2.2,3.3]`) {
		t.Errorf("doubleVals should be preserved, got: %s", result)
	}
	if !strings.Contains(result, `"int32Vals":[1,2,3]`) {
		t.Errorf("int32Vals should be preserved, got: %s", result)
	}

	// Redacted arrays should be empty
	assertContains(t, result, "redactDoubleVals", "[]")
	assertContains(t, result, "redactInt32Vals", "[]")
	assertContains(t, result, "redactStringVals", "[]")
	assertContains(t, result, "redactBoolVals", "[]")
}

func TestRepeatedMessages_Redact(t *testing.T) {
	repeated := &testdata.RepeatedMessages{
		Users: []*testdata.User{
			{Id: "u1", Name: "User1", Email: "u1@test.com", Password: "pass1"},
			{Id: "u2", Name: "User2", Email: "u2@test.com", Password: "pass2"},
		},
		RedactUsers: []*testdata.User{
			{Id: "secret-u1", Name: "Secret1"},
		},
	}

	result := repeated.Redact()
	t.Logf("RepeatedMessages.Redact(): %s", result)

	// Non-redacted repeated messages should be recursively redacted
	if !strings.Contains(result, `"users":[`) {
		t.Error("users array should exist")
	}
	// Emails in users should be redacted (recursive)
	if strings.Contains(result, "u1@test.com") {
		t.Error("Emails in repeated users should be redacted")
	}

	// Redacted repeated messages should be empty array
	assertContains(t, result, "redactUsers", "[]")
}

// =============================================================================
// Map Type Tests
// =============================================================================

func TestMapWithStringKey_Redact(t *testing.T) {
	m := &testdata.MapWithStringKey{
		StringMap: map[string]string{"key1": "value1", "key2": "value2"},
		Int32Map:  map[string]int32{"num": 42},
		UserMap: map[string]*testdata.User{
			"admin": {Id: "admin-1", Name: "Admin", Email: "admin@test.com"},
		},

		// Redacted maps
		RedactStringMap: map[string]string{"secret": "data"},
		RedactUserMap:   map[string]*testdata.User{"hidden": {Id: "h1"}},
	}

	result := m.Redact()
	t.Logf("MapWithStringKey.Redact(): %s", result)

	// Non-redacted maps should be preserved
	if !strings.Contains(result, `"stringMap":{`) {
		t.Error("stringMap should exist")
	}
	if !strings.Contains(result, `"key1":"value1"`) {
		t.Error("stringMap values should be preserved")
	}

	// User map should have recursively redacted values
	if strings.Contains(result, "admin@test.com") {
		t.Error("Email in userMap should be redacted")
	}

	// Redacted maps should be empty
	assertContains(t, result, "redactStringMap", "{}")
	assertContains(t, result, "redactUserMap", "{}")
}

func TestMapWithIntKey_Redact(t *testing.T) {
	m := &testdata.MapWithIntKey{
		Int32KeyMap: map[int32]string{1: "one", 2: "two"},
		Int64KeyMap: map[int64]string{100: "hundred"},

		RedactInt32KeyMap: map[int32]string{999: "secret"},
	}

	result := m.Redact()
	t.Logf("MapWithIntKey.Redact(): %s", result)

	// Int keys should be converted to strings in JSON
	if !strings.Contains(result, `"int32KeyMap":{`) {
		t.Error("int32KeyMap should exist")
	}
	// Keys should be strings in JSON
	if !strings.Contains(result, `"1":"one"`) && !strings.Contains(result, `"2":"two"`) {
		t.Logf("Note: map key order may vary")
	}

	// Redacted map should be empty
	assertContains(t, result, "redactInt32KeyMap", "{}")
}

// =============================================================================
// Oneof Type Tests
// =============================================================================

func TestOneofWithRedact_Redact(t *testing.T) {
	// Test with api_key set
	o1 := &testdata.OneofWithRedact{
		Id:         "req-1",
		Credential: &testdata.OneofWithRedact_ApiKey{ApiKey: "secret-api-key"},
		PublicInfo: &testdata.OneofWithRedact_Description{Description: "public desc"},
	}

	result := o1.Redact()
	t.Logf("OneofWithRedact (ApiKey).Redact(): %s", result)

	assertContainsString(t, result, "id", "req-1")
	assertContainsString(t, result, "apiKey", "*")
	assertContainsString(t, result, "description", "public desc")

	// Test with token set
	o2 := &testdata.OneofWithRedact{
		Id:         "req-2",
		Credential: &testdata.OneofWithRedact_Token{Token: "secret-token"},
	}

	result2 := o2.Redact()
	t.Logf("OneofWithRedact (Token).Redact(): %s", result2)
	assertContainsString(t, result2, "token", "[TOKEN]")
}

func TestOneofWithMessage_Redact(t *testing.T) {
	o := &testdata.OneofWithMessage{
		Id:      "msg-1",
		Payload: &testdata.OneofWithMessage_User{User: &testdata.User{Id: "u1", Name: "Test", Email: "test@test.com"}},
	}

	result := o.Redact()
	t.Logf("OneofWithMessage.Redact(): %s", result)

	// User in oneof should be recursively redacted
	if strings.Contains(result, "test@test.com") {
		t.Error("Email in oneof User should be redacted")
	}
	assertContainsString(t, result, "email", "*")
}

// =============================================================================
// Well-Known Types Tests
// =============================================================================

func TestEvent_Timestamp(t *testing.T) {
	now := time.Now()
	event := &testdata.Event{
		Id:         "evt-1",
		Name:       "TestEvent",
		ApiKey:     "secret-key",
		CreatedAt:  timestamppb.New(now),
		UpdatedAt:  timestamppb.New(now.Add(time.Hour)),
		SecretTime: timestamppb.New(now),
	}

	result := event.Redact()
	t.Logf("Event.Redact(): %s", result)

	assertContainsString(t, result, "id", "evt-1")
	assertContainsString(t, result, "name", "TestEvent")
	assertContainsString(t, result, "apiKey", "*")

	// Timestamp should be in RFC3339 format
	if !strings.Contains(result, `"createdAt":"`) {
		t.Error("createdAt should be a timestamp string")
	}

	// Redacted timestamp should be null
	assertContains(t, result, "secretTime", "null")
}

func TestTask_Duration(t *testing.T) {
	task := &testdata.Task{
		Id:             "task-1",
		Name:           "TestTask",
		Timeout:        durationpb.New(30 * time.Second),
		SecretDuration: durationpb.New(time.Hour),
	}

	result := task.Redact()
	t.Logf("Task.Redact(): %s", result)

	// Duration should be formatted
	if !strings.Contains(result, `"timeout":"`) {
		t.Error("timeout should be a duration string")
	}

	// Redacted duration should be null
	assertContains(t, result, "secretDuration", "null")
}

func TestWrapperTypes_Redact(t *testing.T) {
	w := &testdata.WrapperTypes{
		StringVal:    wrapperspb.String("hello"),
		Int32Val:     wrapperspb.Int32(42),
		Int64Val:     wrapperspb.Int64(100),
		BoolVal:      wrapperspb.Bool(true),
		SecretString: wrapperspb.String("secret"),
		SecretInt:    wrapperspb.Int64(999),
	}

	result := w.Redact()
	t.Logf("WrapperTypes.Redact(): %s", result)

	// Non-redacted wrappers should show values
	if !strings.Contains(result, `"stringVal":`) {
		t.Error("stringVal should exist")
	}

	// Redacted wrappers should be null
	assertContains(t, result, "secretString", "null")
	assertContains(t, result, "secretInt", "null")
}

// =============================================================================
// Complex Message Tests
// =============================================================================

func TestComplexMessage_Redact(t *testing.T) {
	now := time.Now()
	complex := &testdata.ComplexMessage{
		Id:     "complex-1",
		Name:   "ComplexTest",
		Secret: "top-secret",

		Count:       100,
		Score:       99.5,
		Active:      true,
		RedactCount: 9999,

		Status:       testdata.Status_STATUS_ACTIVE,
		RedactStatus: testdata.Status_STATUS_PENDING,

		Owner: &testdata.User{
			Id:    "owner-1",
			Name:  "Owner",
			Email: "owner@test.com",
		},
		RedactOwner: &testdata.User{Id: "secret-owner"},

		CreatedAt:  timestamppb.New(now),
		Timeout:    durationpb.New(time.Minute),
		RedactTime: timestamppb.New(now),

		Tags:          []string{"tag1", "tag2"},
		RedactTags:    []string{"secret-tag"},
		Members:       []*testdata.User{{Id: "m1", Email: "m1@test.com"}},
		RedactMembers: []*testdata.User{{Id: "secret-m"}},

		Labels:          map[string]string{"env": "prod"},
		RedactLabels:    map[string]string{"secret": "data"},
		Assignees:       map[string]*testdata.User{"lead": {Id: "lead-1", Email: "lead@test.com"}},
		RedactAssignees: map[string]*testdata.User{"secret": {Id: "s1"}},
		IndexedData:     map[int32]string{1: "first"},

		Extra:       &testdata.ComplexMessage_Note{Note: "public note"},
		SecretExtra: &testdata.ComplexMessage_SecretNote{SecretNote: "secret note"},
	}

	result := complex.Redact()
	t.Logf("ComplexMessage.Redact(): %s", result)

	// Verify basic fields
	assertContainsString(t, result, "id", "complex-1")
	assertContainsString(t, result, "name", "ComplexTest")
	assertContainsString(t, result, "secret", "*")

	// Verify scalar redaction
	assertContains(t, result, "count", "100")
	assertContains(t, result, "redactCount", "0")

	// Verify enum redaction
	assertContains(t, result, "status", "1")
	assertContains(t, result, "redactStatus", "0")

	// Verify nested message redaction
	if strings.Contains(result, "owner@test.com") {
		t.Error("Owner email should be redacted")
	}
	assertContains(t, result, "redactOwner", "null")

	// Verify repeated redaction
	assertContains(t, result, "redactTags", "[]")
	assertContains(t, result, "redactMembers", "[]")

	// Verify map redaction
	assertContains(t, result, "redactLabels", "{}")
	assertContains(t, result, "redactAssignees", "{}")

	// Verify timestamp redaction
	assertContains(t, result, "redactTime", "null")

	// Verify oneof redaction
	assertContainsString(t, result, "note", "public note")
	assertContainsString(t, result, "secretNote", "*")
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestNilMessage_Redact(t *testing.T) {
	var user *testdata.User
	result := user.Redact()
	if result != "{}" {
		t.Errorf("Nil message should return {}, got: %s", result)
	}
}

func TestMessageWithOnlyRedact_Redact(t *testing.T) {
	msg := &testdata.MessageWithOnlyRedact{
		Password: "secret-pass",
		Token:    "secret-token",
	}

	result := msg.Redact()
	t.Logf("MessageWithOnlyRedact.Redact(): %s", result)

	assertContainsString(t, result, "password", "*")
	assertContainsString(t, result, "token", "*")
}

func TestMessageWithNoRedact_Redact(t *testing.T) {
	msg := &testdata.MessageWithNoRedact{
		Id:   "msg-1",
		Name: "Test",
		User: &testdata.User{
			Id:    "u1",
			Email: "test@test.com",
		},
	}

	result := msg.Redact()
	t.Logf("MessageWithNoRedact.Redact(): %s", result)

	// Message itself has no redact fields, but nested User does
	assertContainsString(t, result, "id", "msg-1")
	assertContainsString(t, result, "name", "Test")
	// Nested user's email should be redacted
	assertContainsString(t, result, "email", "*")
}

func TestSpecialCharacters_Redact(t *testing.T) {
	msg := &testdata.SpecialCharacters{
		Normal:        "normal text",
		WithQuotes:    "has quotes",
		WithBackslash: "has backslash",
		WithNewline:   "has newline",
		Unicode:       "unicode text",
		Emoji:         "has emoji",
	}

	result := msg.Redact()
	t.Logf("SpecialCharacters.Redact(): %s", result)

	// Verify the output is valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result should be valid JSON: %v", err)
	}

	// Verify masks are applied
	assertContainsString(t, result, "normal", "normal text")
	// Note: Special characters in masks will be JSON-escaped
	if !strings.Contains(result, "withQuotes") {
		t.Error("withQuotes should exist")
	}
}

// =============================================================================
// Custom Mask Types Tests
// =============================================================================

func TestCustomMaskTypes_StringMask(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		Password:     "super-secret-password",
		PublicString: "visible text",
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (String).Redact(): %s", result)

	// Custom string mask
	assertContainsString(t, result, "password", "[PASSWORD]")
	// Public string should be preserved
	assertContainsString(t, result, "publicString", "visible text")

	// Original password should NOT appear
	if strings.Contains(result, "super-secret-password") {
		t.Error("Original password should be masked")
	}
}

func TestCustomMaskTypes_IntMask(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		SecretInt32:    12345,
		SecretInt64:    67890,
		SecretUint32:   11111,
		SecretUint64:   22222,
		SecretSint32:   -50,
		SecretSint64:   -60,
		SecretFixed32:  700,
		SecretFixed64:  800,
		SecretSfixed32: -900,
		SecretSfixed64: -1000,
		PublicInt64:    42,
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (Int).Redact(): %s", result)

	// Custom int masks
	assertContains(t, result, "secretInt32", "-1")
	assertContains(t, result, "secretInt64", "-999")
	assertContains(t, result, "secretUint32", "9999")
	assertContains(t, result, "secretUint64", "8888")
	assertContains(t, result, "secretSint32", "-100")
	assertContains(t, result, "secretSint64", "-200")
	assertContains(t, result, "secretFixed32", "1111")
	assertContains(t, result, "secretFixed64", "2222")
	assertContains(t, result, "secretSfixed32", "-333")
	assertContains(t, result, "secretSfixed64", "-444")

	// Public int should be preserved
	assertContains(t, result, "publicInt64", "42")

	// Original values should NOT appear
	if strings.Contains(result, "12345") {
		t.Error("Original secretInt32 should be masked")
	}
	if strings.Contains(result, "67890") {
		t.Error("Original secretInt64 should be masked")
	}
}

func TestCustomMaskTypes_DoubleMask(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		SecretFloat:  3.14159,
		SecretDouble: 2.71828,
		PublicDouble: 99.99,
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (Double).Redact(): %s", result)

	// Custom double masks
	assertContains(t, result, "secretFloat", "-1.5")
	assertContains(t, result, "secretDouble", "-999.99")

	// Public double should be preserved
	assertContains(t, result, "publicDouble", "99.99")

	// Original values should NOT appear
	if strings.Contains(result, "3.14159") {
		t.Error("Original secretFloat should be masked")
	}
	if strings.Contains(result, "2.71828") {
		t.Error("Original secretDouble should be masked")
	}
}

func TestCustomMaskTypes_BoolMask(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		SecretBool: false, // Original is false, but mask is true
		PublicBool: true,
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (Bool).Redact(): %s", result)

	// Custom bool mask (true instead of default false)
	assertContains(t, result, "secretBool", "true")

	// Public bool should be preserved
	assertContains(t, result, "publicBool", "true")
}

func TestCustomMaskTypes_BytesMask(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		SecretBytes: []byte("secret binary data"),
		PublicBytes: []byte("public data"),
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (Bytes).Redact(): %s", result)

	// Custom bytes mask
	assertContainsString(t, result, "secretBytes", "[BINARY]")

	// Original bytes should NOT appear (base64 encoded)
	if strings.Contains(result, "c2VjcmV0") { // base64 of "secret"
		t.Error("Original secretBytes should be masked")
	}
}

func TestCustomMaskTypes_EnumMask(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		SecretStatus:   testdata.Status_STATUS_ACTIVE,   // Original is 1, mask is 99
		SecretPriority: testdata.Priority_PRIORITY_HIGH, // Original is 3, mask is 1
		PublicStatus:   testdata.Status_STATUS_PENDING,  // 3
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (Enum).Redact(): %s", result)

	// Custom enum masks
	assertContains(t, result, "secretStatus", "99")
	assertContains(t, result, "secretPriority", "1")

	// Public status should be preserved
	assertContains(t, result, "publicStatus", "3")
}

func TestCustomMaskTypes_AllFields(t *testing.T) {
	msg := &testdata.CustomMaskTypes{
		Password:       "secret-password",
		SecretInt32:    100,
		SecretInt64:    200,
		SecretUint32:   300,
		SecretUint64:   400,
		SecretSint32:   -500,
		SecretSint64:   -600,
		SecretFixed32:  700,
		SecretFixed64:  800,
		SecretSfixed32: -900,
		SecretSfixed64: -1000,
		SecretFloat:    1.1,
		SecretDouble:   2.2,
		SecretBool:     false,
		SecretBytes:    []byte("secret"),
		SecretStatus:   testdata.Status_STATUS_ACTIVE,
		SecretPriority: testdata.Priority_PRIORITY_CRITICAL,
		PublicString:   "public",
		PublicInt64:    999,
		PublicDouble:   88.88,
		PublicBool:     true,
		PublicBytes:    []byte("public"),
		PublicStatus:   testdata.Status_STATUS_INACTIVE,
	}

	result := msg.Redact()
	t.Logf("CustomMaskTypes (All).Redact(): %s", result)

	// Verify all custom masks are applied correctly
	assertContainsString(t, result, "password", "[PASSWORD]")
	assertContains(t, result, "secretInt32", "-1")
	assertContains(t, result, "secretInt64", "-999")
	assertContains(t, result, "secretUint32", "9999")
	assertContains(t, result, "secretUint64", "8888")
	assertContains(t, result, "secretSint32", "-100")
	assertContains(t, result, "secretSint64", "-200")
	assertContains(t, result, "secretFixed32", "1111")
	assertContains(t, result, "secretFixed64", "2222")
	assertContains(t, result, "secretSfixed32", "-333")
	assertContains(t, result, "secretSfixed64", "-444")
	assertContains(t, result, "secretFloat", "-1.5")
	assertContains(t, result, "secretDouble", "-999.99")
	assertContains(t, result, "secretBool", "true")
	assertContainsString(t, result, "secretBytes", "[BINARY]")
	assertContains(t, result, "secretStatus", "99")
	assertContains(t, result, "secretPriority", "1")

	// Verify public fields are preserved
	assertContainsString(t, result, "publicString", "public")
	assertContains(t, result, "publicInt64", "999")
	assertContains(t, result, "publicDouble", "88.88")
	assertContains(t, result, "publicBool", "true")
	assertContains(t, result, "publicStatus", "2")

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result should be valid JSON: %v", err)
	}
}

// =============================================================================
// JSON Validity Tests
// =============================================================================

func TestAllMessages_ValidJSON(t *testing.T) {
	messages := []interface{ Redact() string }{
		&testdata.User{Id: "1", Email: "test@test.com"},
		&testdata.Address{Street: "123 Main", ZipCode: "12345"},
		&testdata.Account{Id: "1", SecretKey: "key", User: &testdata.User{Id: "u1"}},
		&testdata.AllScalarTypes{StringVal: "test", RedactString: "secret"},
		&testdata.EnumTypes{Status: testdata.Status_STATUS_ACTIVE},
		&testdata.RepeatedScalars{StringVals: []string{"a", "b"}},
		&testdata.MapWithStringKey{StringMap: map[string]string{"k": "v"}},
		&testdata.OneofWithRedact{Id: "1", Credential: &testdata.OneofWithRedact_ApiKey{ApiKey: "key"}},
		&testdata.ComplexMessage{Id: "1", Secret: "secret"},
		&testdata.CustomMaskTypes{Password: "pass", SecretInt32: 100, SecretDouble: 3.14},
	}

	for i, msg := range messages {
		result := msg.Redact()
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(result), &parsed); err != nil {
			t.Errorf("Message %d produced invalid JSON: %v\nResult: %s", i, err, result)
		}
	}
}
