package kent

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"entgo.io/ent"
)

var (
	defaultEncryptor *EntEncryptor
	// ErrNoEncryptor is returned when no encryptor is available (neither instance nor default).
	ErrNoEncryptor = errors.New("encryptor is nil and no default encryptor set")
)

// SetDefaultEncryptor sets the global default encryptor for EncryptedString.
func SetDefaultEncryptor(encryptor *EntEncryptor) {
	defaultEncryptor = encryptor
}

// GetDefaultEncryptor returns the global default encryptor.
func GetDefaultEncryptor() *EntEncryptor {
	return defaultEncryptor
}

// EntEncryptor provides symmetric encryption functionality using AES-GCM mode.
type EntEncryptor struct {
	key       []byte
	gcm       cipher.AEAD // Cache GCM instance for performance
	nonce     []byte      // Fixed nonce derived from key (WARNING: all encryptions use the same nonce)
	nonceSize int         // Cache nonce size for performance
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

	nonceSize := gcm.NonceSize()
	mac := hmac.New(sha256.New, keyBytes)
	nonce := mac.Sum(nil)[:nonceSize]

	return &EntEncryptor{
		key:       keyBytes,
		gcm:       gcm,
		nonce:     nonce,
		nonceSize: nonceSize,
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

// Encrypt encrypts a string using a fixed nonce (derived from key only).
// WARNING: All encryptions use the same nonce, which is a security risk.
// The same plaintext with the same key will always produce the same ciphertext,
// which allows JOIN operations but reveals when the same data is encrypted.
// plaintext: the string to encrypt
func (e *EntEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	// Encrypt
	// Note: nonce is not included in the ciphertext (using fixed nonce derived from key)
	ciphertext := e.gcm.Seal(nil, e.nonce, []byte(plaintext), nil)
	// Return base64-encoded ciphertext
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext and returns plaintext.
// ciphertext: base64-encoded encrypted string (does not include nonce)
func (e *EntEncryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Minimum length check: GCM auth tag is 16 bytes
	minLength := e.gcm.Overhead()
	if len(ciphertextBytes) < minLength {
		return "", errors.New("ciphertext too short")
	}

	// Decrypt using the fixed nonce (nonce is not included in ciphertext)
	plaintext, err := e.gcm.Open(nil, e.nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
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
func (e *EntEncryptor) encryptStringField(fieldName string, value any) (string, error) {
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

				encrypted, err := e.encryptStringField(fieldName, value)
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

// findFieldByJSONTag finds a struct field by its JSON tag name.
// Returns an invalid reflect.Value if not found.
func (e *EntEncryptor) findFieldByJSONTag(rv reflect.Value, jsonTagName string) reflect.Value {
	if !rv.IsValid() {
		return reflect.Value{}
	}
	// dereference pointer
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return reflect.Value{}
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return reflect.Value{}
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		fieldType := rt.Field(i)
		fieldValue := rv.Field(i)
		// handle anonymous nested struct
		if fieldType.Anonymous && fieldValue.Kind() == reflect.Struct {
			if v := e.findFieldByJSONTag(fieldValue, jsonTagName); v.IsValid() {
				return v
			}
		}
		tag := fieldType.Tag.Get("json")
		if tag == "-" {
			continue
		}
		jsonName, _, _ := strings.Cut(tag, ",")
		if jsonName == "" {
			jsonName = fieldType.Name
		}

		if jsonName == jsonTagName {
			return fieldValue
		}
	}
	return reflect.Value{}
}

// decryptStructField decrypts a single field in a struct using reflection.
func (e *EntEncryptor) decryptStructField(rv reflect.Value, fieldName string) error {
	// Try exact match first
	field := rv.FieldByName(fieldName)

	// If still not found, try matching by JSON tag
	if !field.IsValid() {
		field = e.findFieldByJSONTag(rv, fieldName)
	}

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
func (e *EntEncryptor) DecryptEntity(entity any, fields ...string) error {
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
func (e *EntEncryptor) DecryptEntitySlice(entities any, fields ...string) error {
	rv := reflect.ValueOf(entities)
	if rv.Kind() != reflect.Slice {
		return fmt.Errorf("entities must be a slice type")
	}

	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		var entity any
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
func (e *EntEncryptor) DecryptInterceptor(fields ...string) ent.Interceptor {
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
				if err := e.DecryptEntity(value, fieldSlice...); err != nil {
					return nil, err
				}
			case reflect.Slice:
				// Entity slice
				if err := e.DecryptEntitySlice(value, fieldSlice...); err != nil {
					return nil, err
				}
			default:
				// Other types (int, string, etc.) are ignored as they are not entity types
				// This is intentional behavior
			}

			return value, nil
		})
	})
}

// EncryptedString is a string type that automatically encrypts on write and decrypts on read.
// It implements driver.Valuer and sql.Scanner interfaces for database operations.
//
// Usage in Ent schema with GoType (Recommended - supports automatic encryption in WHERE conditions):
//
//	type User struct {
//	    ent.Schema
//	}
//
//	func (User) Fields() []ent.Field {
//	    return []ent.Field{
//	        field.String("email").
//	            GoType(&EncryptedString{}).
//	            SchemaType(map[string]string{
//	                "postgres": "text",
//	                "mysql":    "text",
//	            }),
//	    }
//	}
//
// With GoType, WHERE conditions will automatically call Value() to encrypt:
//
//	// Setup (once at application startup)
//	encryptor, _ := NewEncryptor("my-secret-key")
//	SetDefaultEncryptor(encryptor)
//
//	// Create - using MustEncryptedString() helper
//	user, err := client.User.Create().
//	    SetEmail(MustEncryptedString("user@example.com")).  // Automatically encrypted
//	    Save(ctx)
//
//	// Query - WHERE condition automatically encrypts
//	users, err := client.User.Query().
//	    Where(user.EmailEQ(MustEncryptedString("user@example.com"))).  // Automatically encrypted!
//	    All(ctx)
//
//	// Or use NewEncryptedString() for error handling
//	email, err := NewEncryptedString("user@example.com")
//	if err != nil {
//	    return err
//	}
//	user, err := client.User.Create().
//	    SetEmail(email).  // email is already *EncryptedString
//	    Save(ctx)
//
//	// Read - automatically decrypted
//	fmt.Println(user.Email.String())  // Returns plaintext
//
//	// Note: plaintext field is private, use NewEncryptedString() or MustEncryptedString() helpers
type EncryptedString struct {
	plaintext string        // plaintext value (private field, use String() to access)
	encryptor *EntEncryptor // Encryptor instance for encryption/decryption
}

// NewEncryptedString creates a new EncryptedString using the global default encryptor.
// Returns error if no default encryptor is set.
func NewEncryptedString(plaintext string) (*EncryptedString, error) {
	if defaultEncryptor == nil {
		return nil, errors.New("default encryptor is nil, call SetDefaultEncryptor() first")
	}
	return &EncryptedString{
		plaintext: plaintext,
		encryptor: defaultEncryptor,
	}, nil
}

// MustEncryptedString creates a new EncryptedString using the global default encryptor.
// Panics if no default encryptor is set.
func MustEncryptedString(plaintext string) *EncryptedString {
	encrypted, err := NewEncryptedString(plaintext)
	if err != nil {
		panic(err)
	}
	return encrypted
}

// Value implements driver.Valuer interface - called when writing to database.
// Encrypts the plaintext value before storing.
func (e *EncryptedString) Value() (driver.Value, error) {
	encryptor := e.encryptor
	if encryptor == nil {
		encryptor = defaultEncryptor
	}
	if encryptor == nil {
		return nil, ErrNoEncryptor
	}
	return encryptor.Encrypt(e.plaintext)
}

// Scan implements sql.Scanner interface - called when reading from database.
// Decrypts the ciphertext value after reading.
func (e *EncryptedString) Scan(src any) error {
	encryptor := e.encryptor
	if encryptor == nil {
		encryptor = defaultEncryptor
	}
	if encryptor == nil {
		return ErrNoEncryptor
	}

	var ciphertext string
	switch v := src.(type) {
	case string:
		ciphertext = v
	case []byte:
		ciphertext = string(v)
	case nil:
		e.plaintext = ""
		return nil
	default:
		return fmt.Errorf("unsupported type for EncryptedString: %T", src)
	}

	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	e.plaintext = decrypted
	e.encryptor = encryptor // Cache the encryptor for subsequent operations
	return nil
}

// String returns the plaintext value.
func (e *EncryptedString) String() string {
	return e.plaintext
}
