package ent

import (
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "valid 16-byte key (AES-128)",
			key:     []byte("1234567890123456"), // 16 bytes
			wantErr: false,
		},
		{
			name:    "valid 24-byte key (AES-192)",
			key:     []byte("123456789012345678901234"), // 24 bytes
			wantErr: false,
		},
		{
			name:    "valid 32-byte key (AES-256)",
			key:     []byte("12345678901234567890123456789012"), // 32 bytes
			wantErr: false,
		},
		{
			name:    "invalid key length (15 bytes)",
			key:     []byte("123456789012345"), // 15 bytes
			wantErr: true,
		},
		{
			name:    "invalid key length (33 bytes)",
			key:     []byte("123456789012345678901234567890123"), // 33 bytes
			wantErr: true,
		},
		{
			name:    "empty key",
			key:     []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewEncryptor(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("NewEncryptor() returned nil encryptor")
			}
		})
	}
}

func TestNewEncryptorFromString(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{
			name: "short key (auto-hashed to 32 bytes)",
			key:  "short-key",
		},
		{
			name: "16-byte key",
			key:  "1234567890123456",
		},
		{
			name: "24-byte key",
			key:  "123456789012345678901234",
		},
		{
			name: "32-byte key",
			key:  "12345678901234567890123456789012",
		},
		{
			name: "empty key",
			key:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewEncryptorFromString(tt.key)
			if err != nil {
				t.Errorf("NewEncryptorFromString() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf("NewEncryptorFromString() returned nil encryptor")
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple text",
			plaintext: "hello world",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "special characters",
			plaintext: "!@#$%^&*()_+-=[]{}|;:,.<>?",
		},
		{
			name:      "unicode characters",
			plaintext: "你好世界 🌍",
		},
		{
			name:      "long text",
			plaintext: "This is a very long text that contains many characters and should be encrypted and decrypted correctly without any issues.",
		},
		{
			name:      "email address",
			plaintext: "user@example.com",
		},
		{
			name:      "JSON string",
			plaintext: `{"name":"John","age":30,"email":"john@example.com"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := encryptor.Encrypt(tt.plaintext)
			if err != nil {
				t.Errorf("Encrypt() error = %v", err)
				return
			}

			// Empty string should return empty encrypted string
			if tt.plaintext == "" && encrypted != "" {
				t.Errorf("Encrypt() for empty string should return empty string, got %v", encrypted)
				return
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			// Compare
			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptDeterministic(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "test@example.com"

	// Encrypt the same plaintext multiple times
	encrypted1, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted2, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted3, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// All encryptions should produce the same result (deterministic)
	if encrypted1 != encrypted2 || encrypted2 != encrypted3 {
		t.Errorf("Encrypt() should be deterministic: got different results for same input")
		t.Errorf("encrypted1 = %v", encrypted1)
		t.Errorf("encrypted2 = %v", encrypted2)
		t.Errorf("encrypted3 = %v", encrypted3)
	}

	// Verify it can be decrypted correctly
	decrypted, err := encryptor.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptDifferentKeys(t *testing.T) {
	key1 := []byte("12345678901234567890123456789012") // 32 bytes
	key2 := []byte("abcdefghijklmnopqrstuvwxyz123456") // 32 bytes

	encryptor1, err := NewEncryptor(key1)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	encryptor2, err := NewEncryptor(key2)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	plaintext := "test@example.com"

	// Encrypt with different keys
	encrypted1, err := encryptor1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted2, err := encryptor2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Different keys should produce different ciphertexts
	if encrypted1 == encrypted2 {
		t.Errorf("Encrypt() with different keys should produce different ciphertexts")
	}

	// Each should decrypt correctly with its own key
	decrypted1, err := encryptor1.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if decrypted1 != plaintext {
		t.Errorf("Decrypt() with key1 = %v, want %v", decrypted1, plaintext)
	}

	decrypted2, err := encryptor2.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if decrypted2 != plaintext {
		t.Errorf("Decrypt() with key2 = %v, want %v", decrypted2, plaintext)
	}

	// Decrypting with wrong key should fail
	_, err = encryptor1.Decrypt(encrypted2)
	if err == nil {
		t.Errorf("Decrypt() with wrong key should fail")
	}

	_, err = encryptor2.Decrypt(encrypted1)
	if err == nil {
		t.Errorf("Decrypt() with wrong key should fail")
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	encryptor, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
		wantErr    bool
	}{
		{
			name:       "invalid base64",
			ciphertext: "not-valid-base64!!!",
			wantErr:    true,
		},
		{
			name:       "too short",
			ciphertext: "dGVzdA==", // "test" in base64, too short for GCM
			wantErr:    true,
		},
		{
			name:       "empty string",
			ciphertext: "",
			wantErr:    false, // Empty string should return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.Decrypt(tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

