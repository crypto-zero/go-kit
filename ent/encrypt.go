package ent

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"entgo.io/ent"
)

var (
	defaultEntEncryptor *EntEncryptor
	defaultEncryptorMu  sync.RWMutex
)

// GetDefaultEncryptor returns the default encryptor instance.
// Returns nil if no default encryptor has been set.
func GetDefaultEncryptor() *EntEncryptor {
	defaultEncryptorMu.RLock()
	defer defaultEncryptorMu.RUnlock()
	return defaultEntEncryptor
}

// SetDefaultEncryptor sets the default encryptor instance.
// Returns an error if encryptor is nil.
func SetDefaultEncryptor(encryptor *EntEncryptor) error {
	if encryptor == nil {
		return errors.New("encryptor cannot be nil")
	}
	defaultEncryptorMu.Lock()
	defer defaultEncryptorMu.Unlock()
	defaultEntEncryptor = encryptor
	return nil
}

// EntEncryptor provides symmetric encryption functionality using AES-GCM mode.
// WARNING: This uses deterministic encryption for database JOIN operations,
// but it reveals when the same plaintext is encrypted. Use with caution.
type EntEncryptor struct {
	key []byte
	gcm cipher.AEAD // Cache GCM instance for performance
	mu  sync.RWMutex
}

// NewEncryptor creates an encryptor from a string key (automatically handles key length).
// The key will be hashed to 32 bytes if it's not 16, 24, or 32 bytes long.
// key: the encryption key string (cannot be empty)
func NewEncryptor(key string) (*EntEncryptor, error) {
	if key == "" {
		return nil, errors.New("key cannot be empty")
	}

	keyBytes := []byte(key)
	keyLen := len(keyBytes)

	// If the key length doesn't meet requirements, use SHA256 hash
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		// Use SHA256 to generate a 32-byte key (AES-256)
		hash := sha256.Sum256(keyBytes)
		keyBytes = hash[:]
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EntEncryptor{
		key: keyBytes,
		gcm: gcm,
	}, nil
}

// NewEncryptorFromRSAEncryptedKey creates an encryptor from an RSA-encrypted key ciphertext.
// The encrypted key (ciphertext) will be decrypted using the RSA private key,
// then used as the AES encryption key.
// encryptedKey: base64-encoded ciphertext of the key encrypted with RSA public key
// privateKey: RSA private key used to decrypt the encrypted key (cannot be nil)
func NewEncryptorFromRSAEncryptedKey(encryptedKey string, privateKey *rsa.PrivateKey) (*EntEncryptor, error) {
	if encryptedKey == "" {
		return nil, errors.New("encrypted key cannot be empty")
	}
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	// Decode base64 encrypted key
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Decrypt using RSA private key with OAEP padding
	hash := sha256.New()
	decryptedKey, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, encryptedBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Validate and use the decrypted key
	return NewEncryptor(string(decryptedKey))
}

// Encrypt encrypts a string deterministically and returns base64-encoded ciphertext.
// WARNING: The same plaintext with the same key will always produce the same ciphertext.
// This allows JOIN operations but reveals when the same data is encrypted.
// plaintext: the string to encrypt
func (e *EntEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	e.mu.RLock()
	gcm := e.gcm
	key := e.key // Get key under lock protection
	e.mu.RUnlock()

	if gcm == nil {
		return "", errors.New("encryptor has been cleared or not properly initialized")
	}
	if key == nil {
		return "", errors.New("encryptor has been cleared")
	}

	// Derive nonce from key and plaintext using HMAC-SHA256
	// This ensures the same plaintext always produces the same nonce
	nonceSize := gcm.NonceSize()
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(plaintext))
	nonce := mac.Sum(nil)[:nonceSize]

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return base64-encoded ciphertext
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext and returns plaintext.
// ciphertext: base64-encoded encrypted string
func (e *EntEncryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	e.mu.RLock()
	gcm := e.gcm
	e.mu.RUnlock()

	if gcm == nil {
		return "", errors.New("encryptor has been cleared or not properly initialized")
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// Clear securely clears the encryption key and GCM instance from memory.
// After calling this, the encryptor should not be used.
// This helps prevent key material from remaining in memory.
func (e *EntEncryptor) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear key bytes
	for i := range e.key {
		e.key[i] = 0
	}
	e.key = nil
	e.gcm = nil
}

// fieldSet is a helper type for fast field name lookup
type fieldSet map[string]struct{}

// newFieldSet creates a fieldSet from a slice of field names, filtering out empty strings.
func newFieldSet(fields []string) fieldSet {
	set := make(fieldSet, len(fields))
	for _, f := range fields {
		if f != "" {
			set[f] = struct{}{}
		}
	}
	return set
}

// encryptStringField encrypts a string field value if it's a non-empty string.
// Returns empty string if the value should be skipped (non-string, empty, etc.)
func (e *EntEncryptor) encryptStringField(fieldName string, value interface{}) (string, error) {
	strValue, ok := value.(string)
	if !ok || strValue == "" {
		return "", nil // Skip non-string or empty values
	}

	encrypted, err := e.Encrypt(strValue)
	if err != nil {
		return "", fmt.Errorf("encrypt field %s failed: %w", fieldName, err)
	}
	return encrypted, nil
}

// EncryptHook creates a generic encryption hook for any ent entity.
// It encrypts specified string fields before saving (using deterministic encryption, supports JOIN queries).
// fields: list of field names to encrypt, if empty, no fields will be encrypted.
func (e *EntEncryptor) EncryptHook(fields ...string) ent.Hook {
	encryptor := e
	if encryptor == nil {
		encryptor = GetDefaultEncryptor()
		if encryptor == nil {
			panic("encryptor is nil and no default encryptor is set")
		}
	}

	fieldSet := newFieldSet(fields)
	if len(fieldSet) == 0 {
		// No fields to encrypt, return a no-op hook
		return func(next ent.Mutator) ent.Mutator {
			return next
		}
	}

	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// Encrypt specified fields
			for fieldName := range fieldSet {
				value, exists := m.Field(fieldName)
				if !exists {
					continue // Field doesn't exist or not set, skip
				}

				encrypted, err := encryptor.encryptStringField(fieldName, value)
				if err != nil {
					return nil, err
				}
				if encrypted != "" {
					if err := m.SetField(fieldName, encrypted); err != nil {
						return nil, fmt.Errorf("set encrypted field %s failed: %w", fieldName, err)
					}
				}
			}

			return next.Mutate(ctx, m)
		})
	}
}

// EncryptHookWithDefault creates an encryption hook using the default encryptor.
// This is a convenience function that uses GetDefaultEncryptor().
func EncryptHookWithDefault(fields ...string) ent.Hook {
	encryptor := GetDefaultEncryptor()
	if encryptor == nil {
		panic("no default encryptor is set, call SetDefaultEncryptor() first")
	}
	return encryptor.EncryptHook(fields...)
}

// decryptStructField decrypts a single field in a struct using reflection.
func (e *EntEncryptor) decryptStructField(rv reflect.Value, fieldName string) error {
	field := rv.FieldByName(fieldName)
	if !field.IsValid() || !field.CanSet() {
		return nil // Field doesn't exist or cannot be set, skip silently
	}

	if field.Kind() != reflect.String {
		return nil // Not a string type, skip
	}

	encryptedValue := field.String()
	if encryptedValue == "" {
		return nil // Empty field, skip
	}

	decrypted, err := e.Decrypt(encryptedValue)
	if err != nil {
		return fmt.Errorf("decrypt field %s failed: %w", fieldName, err)
	}

	field.SetString(decrypted)
	return nil
}

// DecryptEntity is a generic decryption function that uses reflection to decrypt specified fields of any entity.
// entity: any ent entity (pointer type, cannot be nil)
// fields: list of field names to decrypt
func (e *EntEncryptor) DecryptEntity(entity interface{}, fields ...string) error {
	fieldSet := newFieldSet(fields)
	if len(fieldSet) == 0 {
		return nil // No fields specified, return directly
	}

	rv := reflect.ValueOf(entity)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("entity must be a pointer type")
	}
	if rv.IsNil() {
		return fmt.Errorf("entity cannot be nil")
	}

	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("entity must point to a struct")
	}

	// Decrypt each field
	for fieldName := range fieldSet {
		if err := e.decryptStructField(rv, fieldName); err != nil {
			return err
		}
	}

	return nil
}

// DecryptEntitySlice decrypts all encrypted fields of entities in a slice.
// entities: slice of entities to decrypt
// fields: list of field names to decrypt
func (e *EntEncryptor) DecryptEntitySlice(entities interface{}, fields ...string) error {
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
		if err := e.DecryptEntity(entity, fields...); err != nil {
			return fmt.Errorf("decrypt entity at index %d failed: %w", i, err)
		}
	}

	return nil
}

// DecryptInterceptor creates a generic decryption interceptor that automatically decrypts fields after queries.
// Works with any ent entity. Automatically handles single entities and slices.
// fields: list of field names to decrypt
// If e is nil, it will use the default encryptor if available.
func (e *EntEncryptor) DecryptInterceptor(fields ...string) ent.Interceptor {
	encryptor := e
	if encryptor == nil {
		encryptor = GetDefaultEncryptor()
		if encryptor == nil {
			panic("encryptor is nil and no default encryptor is set")
		}
	}

	fieldSet := newFieldSet(fields)
	if len(fieldSet) == 0 {
		// No fields to decrypt, return a no-op interceptor
		return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
			return next
		})
	}

	// Convert fieldSet back to slice for DecryptEntity/DecryptEntitySlice
	fieldSlice := make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		fieldSlice = append(fieldSlice, f)
	}

	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			value, err := next.Query(ctx, query)
			if err != nil {
				return value, err
			}

			if value == nil {
				return value, nil
			}

			// Use reflection to handle different return types
			rv := reflect.ValueOf(value)
			switch rv.Kind() {
			case reflect.Ptr:
				// Single entity
				if err := encryptor.DecryptEntity(value, fieldSlice...); err != nil {
					return nil, err
				}
			case reflect.Slice:
				// Entity slice
				if err := encryptor.DecryptEntitySlice(value, fieldSlice...); err != nil {
					return nil, err
				}
				// Other types (int, string, etc.) are ignored as they are not entity types
				// This is intentional behavior
			}

			return value, nil
		})
	})
}

// DecryptInterceptorWithDefault creates a decryption interceptor using the default encryptor.
// This is a convenience function that uses GetDefaultEncryptor().
func DecryptInterceptorWithDefault(fields ...string) ent.Interceptor {
	encryptor := GetDefaultEncryptor()
	if encryptor == nil {
		panic("no default encryptor is set, call SetDefaultEncryptor() first")
	}
	return encryptor.DecryptInterceptor(fields...)
}
