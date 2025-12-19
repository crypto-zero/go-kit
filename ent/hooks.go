package ent

import (
	"context"
	"fmt"
	"reflect"

	"entgo.io/ent"
)

// EncryptHook creates a generic encryption hook for any ent entity.
// It encrypts specified string fields before saving (using deterministic encryption, supports JOIN queries).
// fields: list of field names to encrypt, if empty, no fields will be encrypted.
func EncryptHook(encryptor *EntEncryptor, fields ...string) ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// If no fields specified, skip
			if len(fields) == 0 {
				return next.Mutate(ctx, m)
			}

			// Encrypt specified fields
			for _, fieldName := range fields {
				// Get field value
				value, exists := m.Field(fieldName)
				if !exists {
					continue // Field doesn't exist or not set, skip
				}

				// Check if it's a string type
				strValue, ok := value.(string)
				if !ok {
					continue // Not a string type, skip
				}

				// If field is empty, skip encryption
				if strValue == "" {
					continue
				}

				// Encrypt field value (using deterministic encryption)
				encrypted, err := encryptor.Encrypt(strValue)
				if err != nil {
					return nil, fmt.Errorf("encrypt field %s failed: %w", fieldName, err)
				}

				// Set encrypted value
				if err := m.SetField(fieldName, encrypted); err != nil {
					return nil, fmt.Errorf("set encrypted field %s failed: %w", fieldName, err)
				}
			}

			// Continue to next mutator
			return next.Mutate(ctx, m)
		})
	}
}

// DecryptEntity is a generic decryption function that uses reflection to decrypt specified fields of any entity.
// entity: any ent entity (pointer type)
// fields: list of field names to decrypt
func DecryptEntity(encryptor *EntEncryptor, entity interface{}, fields ...string) error {
	if len(fields) == 0 {
		return nil // No fields specified, return directly
	}

	// Use reflection to get entity value
	rv := reflect.ValueOf(entity)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("entity must be a pointer type")
	}

	// Get the value pointed to
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("entity must point to a struct")
	}

	// Decrypt each field
	for _, fieldName := range fields {
		field := rv.FieldByName(fieldName)
		if !field.IsValid() || !field.CanSet() {
			continue // Field doesn't exist or cannot be set, skip
		}

		// Check if it's a string type
		if field.Kind() != reflect.String {
			continue // Not a string type, skip
		}

		// Get field value
		encryptedValue := field.String()
		if encryptedValue == "" {
			continue // Field is empty, skip
		}

		// Decrypt
		decrypted, err := encryptor.Decrypt(encryptedValue)
		if err != nil {
			return fmt.Errorf("decrypt field %s failed: %w", fieldName, err)
		}

		// Set decrypted value
		field.SetString(decrypted)
	}

	return nil
}

// DecryptEntitySlice decrypts all encrypted fields of entities in a slice.
func DecryptEntitySlice(encryptor *EntEncryptor, entities interface{}, fields ...string) error {
	rv := reflect.ValueOf(entities)
	if rv.Kind() != reflect.Slice {
		return fmt.Errorf("entities must be a slice type")
	}

	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		var entity interface{}
		// Handle both pointer and non-pointer elements
		if elem.Kind() == reflect.Ptr {
			entity = elem.Interface()
		} else {
			entity = elem.Addr().Interface()
		}
		if err := DecryptEntity(encryptor, entity, fields...); err != nil {
			return fmt.Errorf("decrypt entity at index %d failed: %w", i, err)
		}
	}

	return nil
}

// DecryptInterceptor creates a generic decryption interceptor that automatically decrypts fields after queries.
// Works with any ent entity.
func DecryptInterceptor(encryptor *EntEncryptor, fields ...string) ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// Execute original query
			value, err := next.Query(ctx, query)
			if err != nil {
				return value, err
			}

			// If no fields specified, return directly
			if len(fields) == 0 {
				return value, nil
			}

			// Use reflection to handle different return types
			rv := reflect.ValueOf(value)
			switch rv.Kind() {
			case reflect.Ptr:
				// Single entity
				if err := DecryptEntity(encryptor, value, fields...); err != nil {
					return nil, err
				}
			case reflect.Slice:
				// Entity slice
				if err := DecryptEntitySlice(encryptor, value, fields...); err != nil {
					return nil, err
				}
			}

			return value, nil
		})
	})
}
