package ent

import (
	"context"
	"testing"

	"entgo.io/ent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMutation is a simple mock implementation of ent.Mutation for testing
type mockMutation struct {
	fields map[string]interface{}
	op     ent.Op
}

func (m *mockMutation) Op() ent.Op {
	return m.op
}

func (m *mockMutation) Type() string {
	return "Test"
}

func (m *mockMutation) Fields() []string {
	fields := make([]string, 0, len(m.fields))
	for k := range m.fields {
		fields = append(fields, k)
	}
	return fields
}

func (m *mockMutation) Field(name string) (ent.Value, bool) {
	val, ok := m.fields[name]
	return val, ok
}

func (m *mockMutation) SetField(name string, value ent.Value) error {
	m.fields[name] = value
	return nil
}

func (m *mockMutation) AddedFields() []string {
	return nil
}

func (m *mockMutation) AddedField(name string) (ent.Value, bool) {
	return nil, false
}

func (m *mockMutation) AddField(name string, value ent.Value) error {
	return nil
}

func (m *mockMutation) ClearedFields() []string {
	return nil
}

func (m *mockMutation) FieldCleared(name string) bool {
	return false
}

func (m *mockMutation) ClearField(name string) error {
	return nil
}

func (m *mockMutation) OldField(ctx context.Context, name string) (ent.Value, error) {
	return nil, nil
}

func (m *mockMutation) ResetField(name string) error {
	delete(m.fields, name)
	return nil
}

func (m *mockMutation) WhereP(...func(interface{})) {}

func (m *mockMutation) AddedEdges() []string {
	return nil
}

func (m *mockMutation) RemovedEdges() []string {
	return nil
}

func (m *mockMutation) RemovedIDs(name string) []ent.Value {
	return nil
}

func (m *mockMutation) AddedIDs(name string) []ent.Value {
	return nil
}

func (m *mockMutation) ClearedEdges() []string {
	return nil
}

func (m *mockMutation) EdgeCleared(name string) bool {
	return false
}

func (m *mockMutation) ResetEdge(name string) error {
	return nil
}

func (m *mockMutation) ClearEdge(name string) error {
	return nil
}

func (m *mockMutation) Client() interface{} {
	return nil
}

// mockMutator is a simple mock implementation of ent.Mutator for testing
type mockMutator struct {
	value ent.Value
	err   error
}

func (m *mockMutator) Mutate(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
	return m.value, m.err
}

// TestEntity is a simple test entity struct
type TestEntity struct {
	ID       int
	Email    string
	Username string
	Password string
	Age      int
}

func TestEncryptHook(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	require.NoError(t, err)

	tests := []struct {
		name          string
		fields        []string
		mutation      *mockMutation
		expectEncrypt bool
		expectError   bool
	}{
		{
			name:   "encrypt single field",
			fields: []string{"email"},
			mutation: &mockMutation{
				fields: map[string]interface{}{
					"email": "test@example.com",
				},
				op: ent.OpCreate,
			},
			expectEncrypt: true,
			expectError:   false,
		},
		{
			name:   "encrypt multiple fields",
			fields: []string{"email", "username", "password"},
			mutation: &mockMutation{
				fields: map[string]interface{}{
					"email":    "test@example.com",
					"username": "testuser",
					"password": "secret123",
				},
				op: ent.OpCreate,
			},
			expectEncrypt: true,
			expectError:   false,
		},
		{
			name:   "skip empty fields",
			fields: []string{"email", "username"},
			mutation: &mockMutation{
				fields: map[string]interface{}{
					"email":    "test@example.com",
					"username": "",
				},
				op: ent.OpCreate,
			},
			expectEncrypt: true,
			expectError:   false,
		},
		{
			name:   "skip non-string fields",
			fields: []string{"email", "age"},
			mutation: &mockMutation{
				fields: map[string]interface{}{
					"email": "test@example.com",
					"age":   30,
				},
				op: ent.OpCreate,
			},
			expectEncrypt: true,
			expectError:   false,
		},
		{
			name:   "no fields specified",
			fields: []string{},
			mutation: &mockMutation{
				fields: map[string]interface{}{
					"email": "test@example.com",
				},
				op: ent.OpCreate,
			},
			expectEncrypt: false,
			expectError:   false,
		},
		{
			name:   "field not in mutation",
			fields: []string{"email", "nonexistent"},
			mutation: &mockMutation{
				fields: map[string]interface{}{
					"email": "test@example.com",
				},
				op: ent.OpCreate,
			},
			expectEncrypt: true,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values before encryption
			originalValues := make(map[string]string)
			for _, fieldName := range tt.fields {
				if val, exists := tt.mutation.Field(fieldName); exists {
					if strVal, ok := val.(string); ok && strVal != "" {
						originalValues[fieldName] = strVal
					}
				}
			}

			hook := EncryptHook(encryptor, tt.fields...)
			next := &mockMutator{
				value: tt.mutation,
				err:   nil,
			}

			mutator := hook(next)
			result, err := mutator.Mutate(context.Background(), tt.mutation)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			if tt.expectEncrypt {
				// Check that string fields were encrypted
				for fieldName, originalValue := range originalValues {
					encryptedVal, exists := tt.mutation.Field(fieldName)
					if !exists {
						continue
					}

					encryptedStr, ok := encryptedVal.(string)
					if !ok {
						continue
					}

					// Encrypted value should be different from original
					assert.NotEqual(t, originalValue, encryptedStr, "Field %s should be encrypted", fieldName)
					assert.NotEmpty(t, encryptedStr, "Encrypted value should not be empty")

					// Verify it can be decrypted back
					decrypted, err := encryptor.Decrypt(encryptedStr)
					assert.NoError(t, err)
					assert.Equal(t, originalValue, decrypted, "Field %s should decrypt to original value", fieldName)
				}
			}
		})
	}
}

func TestDecryptEntity(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	require.NoError(t, err)

	// Encrypt some test data
	originalEmail := "test@example.com"
	originalUsername := "testuser"
	originalPassword := "secret123"

	encryptedEmail, err := encryptor.Encrypt(originalEmail)
	require.NoError(t, err)

	encryptedUsername, err := encryptor.Encrypt(originalUsername)
	require.NoError(t, err)

	encryptedPassword, err := encryptor.Encrypt(originalPassword)
	require.NoError(t, err)

	tests := []struct {
		name        string
		entity      *TestEntity
		fields      []string
		expectError bool
	}{
		{
			name: "decrypt single field",
			entity: &TestEntity{
				Email: encryptedEmail,
			},
			fields:      []string{"Email"},
			expectError: false,
		},
		{
			name: "decrypt multiple fields",
			entity: &TestEntity{
				Email:    encryptedEmail,
				Username: encryptedUsername,
				Password: encryptedPassword,
			},
			fields:      []string{"Email", "Username", "Password"},
			expectError: false,
		},
		{
			name: "skip empty fields",
			entity: &TestEntity{
				Email:    encryptedEmail,
				Username: "",
			},
			fields:      []string{"Email", "Username"},
			expectError: false,
		},
		{
			name: "skip non-string fields",
			entity: &TestEntity{
				Email: encryptedEmail,
				Age:   30,
			},
			fields:      []string{"Email", "Age"},
			expectError: false,
		},
		{
			name: "no fields specified",
			entity: &TestEntity{
				Email: encryptedEmail,
			},
			fields:      []string{},
			expectError: false,
		},
		{
			name:        "non-pointer entity",
			entity:      &TestEntity{Email: encryptedEmail},
			fields:      []string{"Email"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entity interface{}
			if tt.expectError && tt.name == "non-pointer entity" {
				// Create a non-pointer entity for this test
				nonPtrEntity := TestEntity{Email: encryptedEmail}
				entity = nonPtrEntity
			} else {
				entity = tt.entity
			}

			err := DecryptEntity(encryptor, entity, tt.fields...)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Verify decryption
			if len(tt.fields) > 0 {
				if tt.entity.Email != "" && contains(tt.fields, "Email") {
					assert.Equal(t, originalEmail, tt.entity.Email, "Email should be decrypted")
				}
				if tt.entity.Username != "" && contains(tt.fields, "Username") {
					assert.Equal(t, originalUsername, tt.entity.Username, "Username should be decrypted")
				}
				if tt.entity.Password != "" && contains(tt.fields, "Password") {
					assert.Equal(t, originalPassword, tt.entity.Password, "Password should be decrypted")
				}
			}
		})
	}
}

func TestDecryptEntitySlice(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	require.NoError(t, err)

	// Encrypt test data
	originalEmail := "test@example.com"
	encryptedEmail, err := encryptor.Encrypt(originalEmail)
	require.NoError(t, err)

	originalUsername := "testuser"
	encryptedUsername, err := encryptor.Encrypt(originalUsername)
	require.NoError(t, err)

	entities := []*TestEntity{
		{
			Email:    encryptedEmail,
			Username: encryptedUsername,
		},
		{
			Email:    encryptedEmail,
			Username: encryptedUsername,
		},
	}

	err = DecryptEntitySlice(encryptor, entities, "Email", "Username")
	assert.NoError(t, err)

	// Verify all entities are decrypted
	for i, entity := range entities {
		assert.Equal(t, originalEmail, entity.Email, "Entity %d email should be decrypted", i)
		assert.Equal(t, originalUsername, entity.Username, "Entity %d username should be decrypted", i)
	}
}

func TestDecryptEntitySliceInvalidInput(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	require.NoError(t, err)

	// Test with non-slice
	err = DecryptEntitySlice(encryptor, "not a slice", "Email")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be a slice type")
}

func TestDecryptInterceptor(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	require.NoError(t, err)

	// Encrypt test data
	originalEmail := "test@example.com"
	encryptedEmail, err := encryptor.Encrypt(originalEmail)
	require.NoError(t, err)

	t.Run("decrypt single entity", func(t *testing.T) {
		entity := &TestEntity{
			Email: encryptedEmail,
		}

		interceptor := DecryptInterceptor(encryptor, "Email")

		// Create a mock querier that returns the entity
		mockQuerier := ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			return entity, nil
		})

		querier := interceptor.Intercept(mockQuerier)
		result, err := querier.Query(context.Background(), nil)

		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Verify entity was decrypted
		resultEntity, ok := result.(*TestEntity)
		assert.True(t, ok)
		assert.Equal(t, originalEmail, resultEntity.Email)
	})

	t.Run("decrypt entity slice", func(t *testing.T) {
		entities := []*TestEntity{
			{Email: encryptedEmail},
			{Email: encryptedEmail},
		}

		interceptor := DecryptInterceptor(encryptor, "Email")

		// Create a mock querier that returns the slice
		mockQuerier := ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			return entities, nil
		})

		querier := interceptor.Intercept(mockQuerier)
		result, err := querier.Query(context.Background(), nil)

		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Verify entities were decrypted
		resultSlice, ok := result.([]*TestEntity)
		assert.True(t, ok)
		for _, entity := range resultSlice {
			assert.Equal(t, originalEmail, entity.Email)
		}
	})

	t.Run("no fields specified", func(t *testing.T) {
		entity := &TestEntity{
			Email: encryptedEmail,
		}

		interceptor := DecryptInterceptor(encryptor)

		mockQuerier := ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			return entity, nil
		})

		querier := interceptor.Intercept(mockQuerier)
		result, err := querier.Query(context.Background(), nil)

		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Entity should not be decrypted (no fields specified)
		resultEntity, ok := result.(*TestEntity)
		assert.True(t, ok)
		assert.Equal(t, encryptedEmail, resultEntity.Email)
	})
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
