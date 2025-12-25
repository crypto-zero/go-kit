package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypto-zero/go-kit/protoc-gen-go-redact/testdata"
)

func TestUser_Redact(t *testing.T) {
	tests := []struct {
		name           string
		user           *testdata.User
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:         "nil_user",
			user:         nil,
			wantContains: []string{"{}"},
		},
		{
			name: "user_with_sensitive_fields",
			user: &testdata.User{
				Name:     "John Doe",
				Email:    "john@example.com",
				Password: "secret123",
				Age:      30,
			},
			// Note: protojson serializes int64 as string per proto3 JSON spec
			wantContains:   []string{`"name":"John Doe"`, `"email":"***"`, `"password":"[HIDDEN]"`, `"age":"30"`},
			wantNotContain: []string{"john@example.com", "secret123"},
		},
		{
			name: "user_with_empty_fields",
			user: &testdata.User{},
			// protojson omits zero values by default
			wantContains:   []string{`"email":"***"`, `"password":"[HIDDEN]"`},
			wantNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.user.Redact()

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("Redact() = %v, want to contain %v", got, want)
				}
			}
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(got, notWant) {
					t.Errorf("Redact() = %v, should NOT contain %v", got, notWant)
				}
			}
		})
	}
}

func TestAccount_Redact(t *testing.T) {
	tests := []struct {
		name           string
		account        *testdata.Account
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:         "nil_account",
			account:      nil,
			wantContains: []string{"{}"},
		},
		{
			name: "account_with_sensitive_fields",
			account: &testdata.Account{
				Id:        "acc-123",
				SecretKey: "super-secret-key",
				User: &testdata.User{
					Name:     "Jane",
					Email:    "jane@example.com",
					Password: "password",
					Age:      25,
				},
			},
			wantContains:   []string{`"id":"acc-123"`, `"secretKey":"***SECRET***"`, `"user":`},
			wantNotContain: []string{"super-secret-key"},
		},
		{
			name: "account_without_user",
			account: &testdata.Account{
				Id:        "acc-456",
				SecretKey: "another-secret",
			},
			// protojson omits nil fields by default
			wantContains:   []string{`"id":"acc-456"`, `"secretKey":"***SECRET***"`},
			wantNotContain: []string{"another-secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.account.Redact()

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("Redact() = %v, want to contain %v", got, want)
				}
			}
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(got, notWant) {
					t.Errorf("Redact() = %v, should NOT contain %v", got, notWant)
				}
			}
		})
	}
}

func TestRedact_SensitiveDataNotExposed(t *testing.T) {
	user := &testdata.User{
		Name:     "Alice",
		Email:    "alice@secret.com",
		Password: "my-super-secret-password",
		Age:      28,
	}

	redacted := user.Redact()

	// Verify sensitive data is NOT in the output
	if strings.Contains(redacted, "alice@secret.com") {
		t.Error("email should be redacted")
	}
	if strings.Contains(redacted, "my-super-secret-password") {
		t.Error("password should be redacted")
	}

	// Verify non-sensitive data IS in the output
	if !strings.Contains(redacted, "Alice") {
		t.Error("name should be present")
	}
}

func TestRedact_NestedMessage(t *testing.T) {
	account := &testdata.Account{
		Id:        "acc-789",
		SecretKey: "top-secret",
		User: &testdata.User{
			Name:     "Bob",
			Email:    "bob@example.com",
			Password: "bobpass",
			Age:      35,
		},
	}

	redacted := account.Redact()

	// Account's secret key should be masked
	if strings.Contains(redacted, "top-secret") {
		t.Error("secretKey should be redacted")
	}
	if !strings.Contains(redacted, "***SECRET***") {
		t.Error("secretKey mask should be present")
	}

	// Nested user should be included (but note: User fields are not redacted in Account.Redact)
	if !strings.Contains(redacted, "Bob") {
		t.Error("nested user name should be present")
	}
}

func TestRedact_JSONValid(t *testing.T) {
	user := &testdata.User{
		Name:     "Test User",
		Email:    "test@test.com",
		Password: "testpass",
		Age:      25,
	}

	redacted := user.Redact()

	// Verify output is valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}
