package main

import (
	"testing"
	"time"

	"github.com/crypto-zero/go-kit/logging/protoc-gen-go-redact/testdata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Benchmark Tests for Redact() Performance
// =============================================================================

func BenchmarkRedact_SimpleMessage(b *testing.B) {
	user := &testdata.User{
		Id:       "user-123",
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "secret123",
		Phone:    "+1234567890",
		Age:      30,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = user.Redact()
	}
}

func BenchmarkRedact_NestedMessage(b *testing.B) {
	account := &testdata.Account{
		Id:        "acc-123",
		SecretKey: "super-secret-key",
		User: &testdata.User{
			Id:       "user-1",
			Name:     "Alice",
			Email:    "alice@example.com",
			Password: "pass123",
			Phone:    "+9876543210",
			Age:      25,
		},
		BillingAddress: &testdata.Address{
			Street:  "456 Oak Ave",
			City:    "Los Angeles",
			State:   "CA",
			ZipCode: "90210",
			Country: "USA",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = account.Redact()
	}
}

func BenchmarkRedact_DeepNested(b *testing.B) {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = level1.Redact()
	}
}

func BenchmarkRedact_AllScalarTypes(b *testing.B) {
	scalar := &testdata.AllScalarTypes{
		DoubleVal:          3.14,
		FloatVal:           2.71,
		Int32Val:           100,
		Int64Val:           200,
		Uint32Val:          300,
		Uint64Val:          400,
		Sint32Val:          -50,
		Sint64Val:          -60,
		Fixed32Val:         700,
		Fixed64Val:         800,
		Sfixed32Val:        -900,
		Sfixed64Val:        -1000,
		BoolVal:            true,
		StringVal:          "hello",
		BytesVal:           []byte("world"),
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scalar.Redact()
	}
}

func BenchmarkRedact_RepeatedMessages(b *testing.B) {
	users := make([]*testdata.User, 100)
	for i := 0; i < 100; i++ {
		users[i] = &testdata.User{
			Id:       "user-" + string(rune(i)),
			Name:     "User " + string(rune(i)),
			Email:    "user@example.com",
			Password: "secret",
		}
	}

	repeated := &testdata.RepeatedMessages{
		Users: users,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = repeated.Redact()
	}
}

func BenchmarkRedact_MapWithStringKey(b *testing.B) {
	stringMap := make(map[string]string, 100)
	for i := 0; i < 100; i++ {
		stringMap["key"+string(rune(i))] = "value" + string(rune(i))
	}

	userMap := make(map[string]*testdata.User, 10)
	for i := 0; i < 10; i++ {
		userMap["user"+string(rune(i))] = &testdata.User{
			Id:    "id-" + string(rune(i)),
			Email: "email@test.com",
		}
	}

	m := &testdata.MapWithStringKey{
		StringMap: stringMap,
		UserMap:   userMap,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Redact()
	}
}

func BenchmarkRedact_ComplexMessage(b *testing.B) {
	now := time.Now()
	complex := &testdata.ComplexMessage{
		Id:           "complex-1",
		Name:         "ComplexTest",
		Secret:       "top-secret",
		Count:        100,
		Score:        99.5,
		Active:       true,
		RedactCount:  9999,
		Status:       testdata.Status_STATUS_ACTIVE,
		RedactStatus: testdata.Status_STATUS_PENDING,
		Owner: &testdata.User{
			Id:    "owner-1",
			Name:  "Owner",
			Email: "owner@test.com",
		},
		RedactOwner: &testdata.User{Id: "secret-owner"},
		CreatedAt:   timestamppb.New(now),
		Tags:        []string{"tag1", "tag2", "tag3"},
		RedactTags:  []string{"secret-tag"},
		Members: []*testdata.User{
			{Id: "m1", Email: "m1@test.com"},
			{Id: "m2", Email: "m2@test.com"},
		},
		Labels:       map[string]string{"env": "prod", "team": "backend"},
		RedactLabels: map[string]string{"secret": "data"},
		Assignees:    map[string]*testdata.User{"lead": {Id: "lead-1"}},
		IndexedData:  map[int32]string{1: "first", 2: "second"},
		Extra:        &testdata.ComplexMessage_Note{Note: "public note"},
		SecretExtra:  &testdata.ComplexMessage_SecretNote{SecretNote: "secret note"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = complex.Redact()
	}
}

func BenchmarkRedact_NilMessage(b *testing.B) {
	var user *testdata.User

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = user.Redact()
	}
}

// =============================================================================
// Benchmark Template Execution
// =============================================================================

func BenchmarkTemplateExecute_Simple(b *testing.B) {
	msg := &messageDesc{
		Name: "User",
		Fields: []*fieldDesc{
			{GoName: "Name", JSONName: "name", Redact: false},
			{GoName: "Email", JSONName: "email", Redact: true, StringMask: "*"},
			{GoName: "Password", JSONName: "password", Redact: true, StringMask: "[HIDDEN]"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = msg.execute()
	}
}

func BenchmarkTemplateExecute_Complex(b *testing.B) {
	msg := &messageDesc{
		Name: "ComplexMessage",
		Fields: []*fieldDesc{
			{GoName: "Id", JSONName: "id", Redact: false},
			{GoName: "Name", JSONName: "name", Redact: false},
			{GoName: "Secret", JSONName: "secret", Redact: true, StringMask: "*"},
			{GoName: "Count", JSONName: "count", IsInteger: true, Redact: false},
			{GoName: "RedactCount", JSONName: "redactCount", IsInteger: true, Redact: true},
			{GoName: "Status", JSONName: "status", IsEnum: true, Redact: false},
			{GoName: "Owner", JSONName: "owner", IsMessage: true, Redact: false},
			{GoName: "RedactOwner", JSONName: "redactOwner", IsMessage: true, Redact: true},
			{GoName: "Tags", JSONName: "tags", IsRepeated: true, Redact: false},
			{GoName: "RedactTags", JSONName: "redactTags", IsRepeated: true, Redact: true},
			{GoName: "Labels", JSONName: "labels", IsMap: true, Redact: false},
			{GoName: "RedactLabels", JSONName: "redactLabels", IsMap: true, Redact: true},
			{GoName: "Extra", JSONName: "extra", IsOneof: true, IsMessage: true},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = msg.execute()
	}
}

