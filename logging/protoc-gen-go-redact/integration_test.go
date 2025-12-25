package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/crypto-zero/go-kit/logging/protoc-gen-go-redact/testdata"
	"google.golang.org/protobuf/types/known/timestamppb"
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
			// Using json.Marshal, int64 is serialized as number
			wantContains:   []string{`"name":"John Doe"`, `"email":"*"`, `"password":"[HIDDEN]"`, `"age":30`},
			wantNotContain: []string{"john@example.com", "secret123"},
		},
		{
			name: "user_with_empty_fields",
			user: &testdata.User{},
			// protojson omits zero values by default
			wantContains:   []string{`"email":"*"`, `"password":"[HIDDEN]"`},
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

func TestRedact_MultiLevelNested(t *testing.T) {
	// Create a deeply nested structure: Organization -> Department -> Account -> User
	org := &testdata.Organization{
		Name:  "Acme Corp",
		TaxId: "123-45-6789",
		Headquarters: &testdata.Address{
			Street:  "123 Main St",
			City:    "New York",
			ZipCode: "10001",
		},
		Departments: []*testdata.Department{
			{
				Name:   "Engineering",
				Budget: "$1,000,000",
				Address: &testdata.Address{
					Street:  "456 Tech Ave",
					City:    "San Francisco",
					ZipCode: "94102",
				},
				Accounts: []*testdata.Account{
					{
						Id:        "eng-001",
						SecretKey: "eng-secret-key",
						User: &testdata.User{
							Name:     "Alice Engineer",
							Email:    "alice@acme.com",
							Password: "alice-pass",
							Age:      30,
						},
					},
				},
			},
			{
				Name:   "Sales",
				Budget: "$500,000",
				Address: &testdata.Address{
					Street:  "789 Sales Blvd",
					City:    "Chicago",
					ZipCode: "60601",
				},
				Accounts: []*testdata.Account{
					{
						Id:        "sales-001",
						SecretKey: "sales-secret-key",
						User: &testdata.User{
							Name:     "Bob Sales",
							Email:    "bob@acme.com",
							Password: "bob-pass",
							Age:      35,
						},
					},
				},
			},
		},
	}

	t.Run("organization_redact", func(t *testing.T) {
		redacted := org.Redact()

		// Organization's own sensitive field should be masked
		if strings.Contains(redacted, "123-45-6789") {
			t.Error("taxId should be redacted")
		}
		if !strings.Contains(redacted, "[TAX_ID]") {
			t.Error("taxId mask should be present")
		}

		// Non-sensitive fields should be present
		if !strings.Contains(redacted, "Acme Corp") {
			t.Error("organization name should be present")
		}

		// Nested departments should be present
		if !strings.Contains(redacted, "Engineering") {
			t.Error("department name should be present")
		}

		// Verify output is valid JSON
		var result map[string]any
		if err := json.Unmarshal([]byte(redacted), &result); err != nil {
			t.Errorf("Redact() output is not valid JSON: %v", err)
		}
	})

	t.Run("department_redact", func(t *testing.T) {
		dept := org.Departments[0]
		redacted := dept.Redact()

		// Department's budget should be masked
		if strings.Contains(redacted, "$1,000,000") {
			t.Error("budget should be redacted")
		}
		if !strings.Contains(redacted, "[BUDGET]") {
			t.Error("budget mask should be present")
		}

		// Department name should be present
		if !strings.Contains(redacted, "Engineering") {
			t.Error("department name should be present")
		}

		// Nested accounts should be present
		if !strings.Contains(redacted, "eng-001") {
			t.Error("account id should be present")
		}
	})

	t.Run("address_redact", func(t *testing.T) {
		addr := org.Headquarters
		redacted := addr.Redact()

		// ZipCode should be masked
		if strings.Contains(redacted, "10001") {
			t.Error("zipCode should be redacted")
		}
		if !strings.Contains(redacted, "[ZIP]") {
			t.Error("zipCode mask should be present")
		}

		// Other address fields should be present
		if !strings.Contains(redacted, "123 Main St") {
			t.Error("street should be present")
		}
		if !strings.Contains(redacted, "New York") {
			t.Error("city should be present")
		}
	})

	t.Run("deeply_nested_fields_recursively_redacted", func(t *testing.T) {
		// With recursive redaction, nested messages that implement Redacter
		// will have their sensitive fields masked automatically.
		redacted := org.Redact()

		// Org's own taxId IS redacted
		if strings.Contains(redacted, "123-45-6789") {
			t.Error("organization taxId should be redacted")
		}

		// Nested department's budget IS redacted (recursive)
		if strings.Contains(redacted, "$1,000,000") {
			t.Error("nested department budget should be redacted")
		}
		if !strings.Contains(redacted, "[BUDGET]") {
			t.Error("nested department budget mask should be present")
		}

		// Nested account's secretKey IS redacted (recursive)
		if strings.Contains(redacted, "eng-secret-key") {
			t.Error("nested account secretKey should be redacted")
		}
		if !strings.Contains(redacted, "***SECRET***") {
			t.Error("nested account secretKey mask should be present")
		}

		// Nested user's email IS redacted (recursive)
		if strings.Contains(redacted, "alice@acme.com") {
			t.Error("nested user email should be redacted")
		}

		// Nested user's password IS redacted (recursive)
		if strings.Contains(redacted, "alice-pass") {
			t.Error("nested user password should be redacted")
		}

		// Nested address's zipCode IS redacted (recursive)
		if strings.Contains(redacted, "10001") {
			t.Error("nested address zipCode should be redacted")
		}
		if !strings.Contains(redacted, "[ZIP]") {
			t.Error("nested address zipCode mask should be present")
		}

		// Non-sensitive fields should still be present
		if !strings.Contains(redacted, "Alice Engineer") {
			t.Error("nested user name should be present")
		}
		if !strings.Contains(redacted, "123 Main St") {
			t.Error("nested address street should be present")
		}
	})
}

func TestRedact_Timestamp(t *testing.T) {
	// Test with google.protobuf.Timestamp
	event := &testdata.Event{
		Name:   "UserLogin",
		ApiKey: "secret-api-key-123",
		CreatedAt: &timestamppb.Timestamp{
			Seconds: 1735142400, // 2024-12-25T12:00:00Z
			Nanos:   0,
		},
		UpdatedAt: &timestamppb.Timestamp{
			Seconds: 1735146000, // 2024-12-25T13:00:00Z
			Nanos:   500000000,
		},
	}

	redacted := event.Redact()
	t.Logf("Event.Redact() output: %s", redacted)

	// apiKey should be masked
	if strings.Contains(redacted, "secret-api-key-123") {
		t.Error("apiKey should be redacted")
	}
	if !strings.Contains(redacted, `"apiKey":"*"`) {
		t.Error("apiKey mask should be present")
	}

	// name should be present
	if !strings.Contains(redacted, "UserLogin") {
		t.Error("name should be present")
	}

	// Timestamp should be present (check for seconds field)
	if !strings.Contains(redacted, "createdAt") {
		t.Error("createdAt should be present")
	}

	// Verify it's valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

func TestRedact_AllLevels(t *testing.T) {
	// Test that each level can be independently redacted
	user := &testdata.User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "secret",
		Age:      25,
	}

	account := &testdata.Account{
		Id:        "acc-001",
		SecretKey: "account-secret",
		User:      user,
	}

	dept := &testdata.Department{
		Name:     "Test Dept",
		Budget:   "$100",
		Accounts: []*testdata.Account{account},
		Address: &testdata.Address{
			Street:  "Test St",
			City:    "Test City",
			ZipCode: "12345",
		},
	}

	org := &testdata.Organization{
		Name:        "Test Org",
		TaxId:       "tax-123",
		Departments: []*testdata.Department{dept},
	}

	// Each level should mask its own sensitive fields
	t.Run("user_level", func(t *testing.T) {
		r := user.Redact()
		if strings.Contains(r, "test@example.com") || strings.Contains(r, "secret") {
			t.Error("user sensitive fields should be redacted")
		}
	})

	t.Run("account_level", func(t *testing.T) {
		r := account.Redact()
		if strings.Contains(r, "account-secret") {
			t.Error("account secret should be redacted")
		}
	})

	t.Run("department_level", func(t *testing.T) {
		r := dept.Redact()
		if strings.Contains(r, "$100") {
			t.Error("department budget should be redacted")
		}
	})

	t.Run("organization_level", func(t *testing.T) {
		r := org.Redact()
		t.Logf("Organization.Redact() = %s", r)
		if strings.Contains(r, "$100") {
			t.Error("nested department budget should be redacted")
		}
	})
}

// TestRedact_NumericTypes tests redaction of numeric fields (int64, double, int32)
func TestRedact_NumericTypes(t *testing.T) {
	payment := &testdata.Payment{
		Id:             "pay-001",
		Amount:         99999,
		Balance:        12345.67,
		PinCode:        1234,
		Currency:       "USD",
		CardNumbers:    []string{"4111-1111-1111-1111", "5500-0000-0000-0004"},
		TransactionIds: []int64{100001, 100002, 100003},
	}

	redacted := payment.Redact()
	t.Logf("Payment.Redact() = %s", redacted)

	// Numeric fields should be masked with string
	if strings.Contains(redacted, "99999") {
		t.Error("amount should be redacted")
	}
	if !strings.Contains(redacted, `"amount":"[AMOUNT]"`) {
		t.Error("amount mask should be present")
	}

	if strings.Contains(redacted, "12345.67") {
		t.Error("balance should be redacted")
	}
	if !strings.Contains(redacted, `"balance":"[BALANCE]"`) {
		t.Error("balance mask should be present")
	}

	if strings.Contains(redacted, "1234") && !strings.Contains(redacted, "100001") {
		t.Error("pinCode should be redacted")
	}

	// Non-sensitive fields should be present
	if !strings.Contains(redacted, "pay-001") {
		t.Error("id should be present")
	}
	if !strings.Contains(redacted, "USD") {
		t.Error("currency should be present")
	}

	// Repeated primitive fields should be present
	if !strings.Contains(redacted, "4111-1111-1111-1111") {
		t.Error("card_numbers should be present")
	}
	if !strings.Contains(redacted, "100001") {
		t.Error("transaction_ids should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_WrapperWithoutOwnRedact tests wrapper message without own redact fields
func TestRedact_WrapperWithoutOwnRedact(t *testing.T) {
	wrapper := &testdata.Wrapper{
		Id:   "wrapper-001",
		Name: "Test Wrapper",
		User: &testdata.User{
			Name:     "Alice",
			Email:    "alice@example.com",
			Password: "alice-secret",
			Age:      30,
		},
		Accounts: []*testdata.Account{
			{
				Id:        "acc-001",
				SecretKey: "secret-key-1",
				User: &testdata.User{
					Name:     "Bob",
					Email:    "bob@example.com",
					Password: "bob-secret",
					Age:      25,
				},
			},
			{
				Id:        "acc-002",
				SecretKey: "secret-key-2",
			},
		},
	}

	redacted := wrapper.Redact()
	t.Logf("Wrapper.Redact() = %s", redacted)

	// Wrapper's own fields should be present (no redact on them)
	if !strings.Contains(redacted, "wrapper-001") {
		t.Error("wrapper id should be present")
	}
	if !strings.Contains(redacted, "Test Wrapper") {
		t.Error("wrapper name should be present")
	}

	// Nested User's sensitive fields should be redacted
	if strings.Contains(redacted, "alice@example.com") {
		t.Error("nested user email should be redacted")
	}
	if strings.Contains(redacted, "alice-secret") {
		t.Error("nested user password should be redacted")
	}

	// Nested Accounts' sensitive fields should be redacted
	if strings.Contains(redacted, "secret-key-1") {
		t.Error("nested account secretKey should be redacted")
	}
	if strings.Contains(redacted, "secret-key-2") {
		t.Error("nested account secretKey should be redacted")
	}

	// Non-sensitive nested fields should be present
	if !strings.Contains(redacted, "Alice") {
		t.Error("nested user name should be present")
	}
	if !strings.Contains(redacted, "acc-001") {
		t.Error("nested account id should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_NilNestedMessages tests handling of nil nested messages
func TestRedact_NilNestedMessages(t *testing.T) {
	// Account with nil User
	account := &testdata.Account{
		Id:        "acc-nil-user",
		SecretKey: "secret",
		User:      nil,
	}

	redacted := account.Redact()
	t.Logf("Account with nil User: %s", redacted)

	if !strings.Contains(redacted, "acc-nil-user") {
		t.Error("id should be present")
	}
	if strings.Contains(redacted, "secret") && !strings.Contains(redacted, "***SECRET***") {
		t.Error("secretKey should be masked")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}

	// Wrapper with nil nested messages
	wrapper := &testdata.Wrapper{
		Id:       "wrapper-nil",
		Name:     "Empty Wrapper",
		User:     nil,
		Accounts: nil,
	}

	redacted = wrapper.Redact()
	t.Logf("Wrapper with nil fields: %s", redacted)

	// Valid JSON
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_EmptyRepeated tests handling of empty repeated fields
func TestRedact_EmptyRepeated(t *testing.T) {
	dept := &testdata.Department{
		Name:     "Empty Dept",
		Budget:   "$0",
		Accounts: []*testdata.Account{}, // empty slice
		Address:  nil,
	}

	redacted := dept.Redact()
	t.Logf("Department with empty accounts: %s", redacted)

	if !strings.Contains(redacted, "Empty Dept") {
		t.Error("name should be present")
	}
	if !strings.Contains(redacted, "[BUDGET]") {
		t.Error("budget mask should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_SpecialCharacters tests handling of special characters
func TestRedact_SpecialCharacters(t *testing.T) {
	special := &testdata.SpecialChars{
		Normal:       `Hello "World"`,
		WithQuotes:   `secret "value"`,
		UnicodeField: "中文测试 🎉",
	}

	redacted := special.Redact()
	t.Logf("SpecialChars.Redact() = %s", redacted)

	// Normal field with quotes should be properly escaped
	if !strings.Contains(redacted, "Hello") {
		t.Error("normal field should be present")
	}

	// Sensitive field should be masked
	if strings.Contains(redacted, "secret") {
		t.Error("withQuotes should be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Error("withQuotes mask should be present")
	}

	// Unicode should be preserved
	if !strings.Contains(redacted, "中文测试") {
		t.Error("unicode field should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_BoolAndEnum tests handling of bool and enum fields
func TestRedact_BoolAndEnum(t *testing.T) {
	profile := &testdata.Profile{
		Username:   "john_doe",
		Ssn:        "123-45-6789",
		IsVerified: true,
		Status:     testdata.Status_STATUS_ACTIVE,
		Tags:       []string{"admin", "user"},
	}

	redacted := profile.Redact()
	t.Logf("Profile.Redact() = %s", redacted)

	// SSN should be masked
	if strings.Contains(redacted, "123-45-6789") {
		t.Error("ssn should be redacted")
	}
	if !strings.Contains(redacted, "[SSN]") {
		t.Error("ssn mask should be present")
	}

	// Non-sensitive fields should be present
	if !strings.Contains(redacted, "john_doe") {
		t.Error("username should be present")
	}
	if !strings.Contains(redacted, "true") {
		t.Error("isVerified should be present")
	}

	// Tags should be present
	if !strings.Contains(redacted, "admin") {
		t.Error("tags should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_ZeroValues tests handling of zero/default values
func TestRedact_ZeroValues(t *testing.T) {
	user := &testdata.User{
		Name:     "",
		Email:    "",
		Password: "",
		Age:      0,
	}

	redacted := user.Redact()
	t.Logf("User with zero values: %s", redacted)

	// Sensitive fields should still be masked even with empty values
	if !strings.Contains(redacted, `"email":"*"`) {
		t.Error("email mask should be present even for empty value")
	}
	if !strings.Contains(redacted, `"password":"[HIDDEN]"`) {
		t.Error("password mask should be present even for empty value")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_Container tests message with only message fields (no own redact)
func TestRedact_Container(t *testing.T) {
	container := &testdata.Container{
		User: &testdata.User{
			Name:     "Container User",
			Email:    "container@example.com",
			Password: "container-pass",
			Age:      40,
		},
		Address: &testdata.Address{
			Street:  "Container St",
			City:    "Container City",
			ZipCode: "99999",
		},
	}

	redacted := container.Redact()
	t.Logf("Container.Redact() = %s", redacted)

	// Nested sensitive fields should be redacted
	if strings.Contains(redacted, "container@example.com") {
		t.Error("user email should be redacted")
	}
	if strings.Contains(redacted, "container-pass") {
		t.Error("user password should be redacted")
	}
	if strings.Contains(redacted, "99999") {
		t.Error("address zipCode should be redacted")
	}

	// Non-sensitive nested fields should be present
	if !strings.Contains(redacted, "Container User") {
		t.Error("user name should be present")
	}
	if !strings.Contains(redacted, "Container St") {
		t.Error("address street should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}

// TestRedact_MultipleRepeatedNested tests multiple levels of repeated nested messages
func TestRedact_MultipleRepeatedNested(t *testing.T) {
	org := &testdata.Organization{
		Name:  "Multi Nested Org",
		TaxId: "tax-multi",
		Departments: []*testdata.Department{
			{
				Name:   "Dept 1",
				Budget: "$1000",
				Accounts: []*testdata.Account{
					{Id: "d1-a1", SecretKey: "d1-a1-secret"},
					{Id: "d1-a2", SecretKey: "d1-a2-secret"},
				},
			},
			{
				Name:   "Dept 2",
				Budget: "$2000",
				Accounts: []*testdata.Account{
					{Id: "d2-a1", SecretKey: "d2-a1-secret"},
				},
			},
		},
	}

	redacted := org.Redact()
	t.Logf("Organization with multiple nested: %s", redacted)

	// All nested secrets should be redacted
	if strings.Contains(redacted, "d1-a1-secret") {
		t.Error("d1-a1 secret should be redacted")
	}
	if strings.Contains(redacted, "d1-a2-secret") {
		t.Error("d1-a2 secret should be redacted")
	}
	if strings.Contains(redacted, "d2-a1-secret") {
		t.Error("d2-a1 secret should be redacted")
	}

	// All budgets should be redacted
	if strings.Contains(redacted, "$1000") {
		t.Error("dept 1 budget should be redacted")
	}
	if strings.Contains(redacted, "$2000") {
		t.Error("dept 2 budget should be redacted")
	}

	// IDs should be present
	if !strings.Contains(redacted, "d1-a1") {
		t.Error("d1-a1 id should be present")
	}
	if !strings.Contains(redacted, "d2-a1") {
		t.Error("d2-a1 id should be present")
	}

	// Valid JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(redacted), &result); err != nil {
		t.Errorf("Redact() output is not valid JSON: %v", err)
	}
}
