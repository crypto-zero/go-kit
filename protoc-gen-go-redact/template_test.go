package main

import (
	"strings"
	"testing"
)

func TestMessageDesc_Execute(t *testing.T) {
	tests := []struct {
		name    string
		msgDesc *messageDesc
		want    string
	}{
		{
			name: "simple_message_with_redact",
			msgDesc: &messageDesc{
				Name: "User",
				Fields: []*fieldDesc{
					{GoName: "Name", JSONName: "name", Redact: false, Mask: "***"},
					{GoName: "Email", JSONName: "email", Redact: true, Mask: "***"},
					{GoName: "Password", JSONName: "password", Redact: true, Mask: "***"},
				},
			},
			want: `// Redact returns a redacted JSON string representation of User.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
func (x *User) Redact() string {
	if x == nil {
		return "{}"
	}
	m := make(map[string]any)
	m["name"] = x.Name
	m["email"] = "***"
	m["password"] = "***"
	b, _ := json.Marshal(m)
	return string(b)
}`,
		},
		{
			name: "custom_mask",
			msgDesc: &messageDesc{
				Name: "Account",
				Fields: []*fieldDesc{
					{GoName: "ID", JSONName: "id", Redact: false, Mask: "***"},
					{GoName: "SecretKey", JSONName: "secretKey", Redact: true, Mask: "[REDACTED]"},
				},
			},
			want: `// Redact returns a redacted JSON string representation of Account.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
func (x *Account) Redact() string {
	if x == nil {
		return "{}"
	}
	m := make(map[string]any)
	m["id"] = x.ID
	m["secretKey"] = "[REDACTED]"
	b, _ := json.Marshal(m)
	return string(b)
}`,
		},
		{
			name: "all_fields_normal",
			msgDesc: &messageDesc{
				Name: "PublicData",
				Fields: []*fieldDesc{
					{GoName: "Title", JSONName: "title", Redact: false, Mask: "***"},
					{GoName: "Description", JSONName: "description", Redact: false, Mask: "***"},
				},
			},
			want: `// Redact returns a redacted JSON string representation of PublicData.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
func (x *PublicData) Redact() string {
	if x == nil {
		return "{}"
	}
	m := make(map[string]any)
	m["title"] = x.Title
	m["description"] = x.Description
	b, _ := json.Marshal(m)
	return string(b)
}`,
		},
		{
			name: "all_fields_redacted",
			msgDesc: &messageDesc{
				Name: "Sensitive",
				Fields: []*fieldDesc{
					{GoName: "SSN", JSONName: "ssn", Redact: true, Mask: "***"},
					{GoName: "CreditCard", JSONName: "creditCard", Redact: true, Mask: "****-****-****-****"},
				},
			},
			want: `// Redact returns a redacted JSON string representation of Sensitive.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
func (x *Sensitive) Redact() string {
	if x == nil {
		return "{}"
	}
	m := make(map[string]any)
	m["ssn"] = "***"
	m["creditCard"] = "****-****-****-****"
	b, _ := json.Marshal(m)
	return string(b)
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msgDesc.execute()
			// Normalize whitespace for comparison
			gotNorm := normalizeWhitespace(got)
			wantNorm := normalizeWhitespace(tt.want)

			if gotNorm != wantNorm {
				t.Errorf("messageDesc.execute() mismatch\ngot:\n%s\n\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestMessageDesc_Execute_EmptyFields(t *testing.T) {
	msgDesc := &messageDesc{
		Name:   "Empty",
		Fields: []*fieldDesc{},
	}

	got := msgDesc.execute()
	if !strings.Contains(got, "func (x *Empty) Redact() string") {
		t.Errorf("Expected function signature for Empty message, got: %s", got)
	}
}

func TestFieldDesc(t *testing.T) {
	tests := []struct {
		name  string
		field *fieldDesc
	}{
		{
			name: "default_mask",
			field: &fieldDesc{
				GoName:   "Password",
				JSONName: "password",
				Redact:   true,
				Mask:     "***",
			},
		},
		{
			name: "custom_mask",
			field: &fieldDesc{
				GoName:   "SecretKey",
				JSONName: "secretKey",
				Redact:   true,
				Mask:     "[HIDDEN]",
			},
		},
		{
			name: "no_redact",
			field: &fieldDesc{
				GoName:   "Username",
				JSONName: "username",
				Redact:   false,
				Mask:     "***",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.field.GoName == "" {
				t.Error("GoName should not be empty")
			}
			if tt.field.JSONName == "" {
				t.Error("JSONName should not be empty")
			}
			if tt.field.Mask == "" {
				t.Error("Mask should not be empty")
			}
		})
	}
}

// normalizeWhitespace removes leading/trailing whitespace and normalizes line endings
func normalizeWhitespace(s string) string {
	// Replace \r\n with \n
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// Trim leading and trailing whitespace
	s = strings.TrimSpace(s)
	return s
}
