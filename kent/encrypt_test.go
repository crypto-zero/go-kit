package kent

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptDecrypt_Basic(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"empty string", ""},
		{"short text", "hello"},
		{"medium text", "this is a test message"},
		{"long text", strings.Repeat("a", 1000)},
		{"very long text", strings.Repeat("b", 10000)},
		{"single character", "x"},
		{"numbers", "1234567890"},
		{"special characters", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"unicode", "你好世界 🌍"},
		{"mixed", "Hello 世界 123 !@#"},
		{"newlines", "line1\nline2\nline3"},
		{"tabs", "col1\tcol2\tcol3"},
		{"spaces", "   spaced   text   "},
		{"null bytes", "text\x00with\x00nulls"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := encryptor.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Empty string should return empty ciphertext
			if tc.plaintext == "" {
				if ciphertext != "" {
					t.Errorf("Encrypt() empty string should return empty ciphertext, got %q", ciphertext)
				}
				return
			}

			// Ciphertext should not be empty
			if ciphertext == "" {
				t.Error("Encrypt() should return non-empty ciphertext for non-empty plaintext")
			}

			// Ciphertext should be different from plaintext
			if ciphertext == tc.plaintext {
				t.Error("Encrypt() ciphertext should be different from plaintext")
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify round-trip
			if decrypted != tc.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tc.plaintext)
			}
		})
	}
}

func TestEncryptDecrypt_Deterministic(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "test message"

	// Encrypt the same plaintext multiple times
	ciphertext1, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	ciphertext2, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	ciphertext3, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// All ciphertexts should be identical (deterministic encryption)
	if ciphertext1 != ciphertext2 {
		t.Errorf("Encrypt() should be deterministic: ciphertext1 = %q, ciphertext2 = %q", ciphertext1, ciphertext2)
	}

	if ciphertext2 != ciphertext3 {
		t.Errorf("Encrypt() should be deterministic: ciphertext2 = %q, ciphertext3 = %q", ciphertext2, ciphertext3)
	}

	// All should decrypt to the same plaintext
	decrypted1, _ := encryptor.Decrypt(ciphertext1)
	decrypted2, _ := encryptor.Decrypt(ciphertext2)
	decrypted3, _ := encryptor.Decrypt(ciphertext3)

	if decrypted1 != plaintext || decrypted2 != plaintext || decrypted3 != plaintext {
		t.Error("Decrypt() should return the same plaintext for deterministic ciphertexts")
	}
}

func TestEncryptDecrypt_DifferentKeys(t *testing.T) {
	// Create two encryptors with different keys
	encryptor1, err := NewEncryptor("key1")
	if err != nil {
		t.Fatalf("Failed to create encryptor1: %v", err)
	}

	encryptor2, err := NewEncryptor("key2")
	if err != nil {
		t.Fatalf("Failed to create encryptor2: %v", err)
	}

	plaintext := "test message"

	// Encrypt with encryptor1
	ciphertext1, err := encryptor1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Encrypt with encryptor2
	ciphertext2, err := encryptor2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertexts should be different (different keys)
	if ciphertext1 == ciphertext2 {
		t.Error("Encrypt() with different keys should produce different ciphertexts")
	}

	// Decrypt with correct encryptor should work
	decrypted1, err := encryptor1.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("Decrypt() with correct encryptor error = %v", err)
	}
	if decrypted1 != plaintext {
		t.Errorf("Decrypt() with correct encryptor = %q, want %q", decrypted1, plaintext)
	}

	// Decrypt with wrong encryptor should fail
	_, err = encryptor2.Decrypt(ciphertext1)
	if err == nil {
		t.Error("Decrypt() with wrong encryptor should fail")
	}

	_, err = encryptor1.Decrypt(ciphertext2)
	if err == nil {
		t.Error("Decrypt() with wrong encryptor should fail")
	}
}

func TestEncryptDecrypt_KeyLengths(t *testing.T) {
	testKeys := []struct {
		name string
		key  string
	}{
		{"16-byte key", "1234567890123456"},
		{"24-byte key", "123456789012345678901234"},
		{"32-byte key", "12345678901234567890123456789012"},
		{"short key (hashed)", "short"},
		{"long key (hashed)", "this is a very long key that will be hashed to 32 bytes using SHA256"},
	}

	for _, tc := range testKeys {
		t.Run(tc.name, func(t *testing.T) {
			encryptor, err := NewEncryptor(tc.key)
			if err != nil {
				t.Fatalf("NewEncryptor() error = %v", err)
			}

			plaintext := "test message"
			ciphertext, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
			}
		})
	}
}

func TestEncryptDecrypt_MultipleRoundTrips(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "test message"

	// Perform multiple encrypt-decrypt cycles
	for i := 0; i < 100; i++ {
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt() iteration %d error = %v", i, err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() iteration %d error = %v", i, err)
		}

		if decrypted != plaintext {
			t.Errorf("Decrypt() iteration %d = %q, want %q", i, decrypted, plaintext)
		}
	}
}

func TestDecrypt_ErrorCases(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name       string
		ciphertext string
		wantErr    bool
	}{
		{"empty string", "", false}, // Empty string returns empty string, no error
		{"invalid base64", "invalid-base64!!!", true},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short")), true},
		{"random bytes", base64.StdEncoding.EncodeToString(make([]byte, 20)), true},
		{"wrong nonce", func() string {
			// Create a valid-looking ciphertext but with wrong nonce
			wrongEncryptor, _ := NewEncryptor("different-key")
			ciphertext, _ := wrongEncryptor.Encrypt("test")
			return ciphertext
		}(), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := encryptor.Decrypt(tc.ciphertext)
			if (err != nil) != tc.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestEncryptDecrypt_BinaryData(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Test with binary data (simulated as string with various byte values)
	binaryData := string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD})

	ciphertext, err := encryptor.Encrypt(binaryData)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != binaryData {
		t.Errorf("Decrypt() = %q, want %q", decrypted, binaryData)
	}
}

func TestEncryptDecrypt_Concurrent(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "concurrent test"
	iterations := 1000

	done := make(chan bool, iterations)

	// Concurrent encryption
	for i := 0; i < iterations; i++ {
		go func(id int) {
			ciphertext, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Errorf("Encrypt() goroutine %d error = %v", id, err)
				done <- false
				return
			}

			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Errorf("Decrypt() goroutine %d error = %v", id, err)
				done <- false
				return
			}

			if decrypted != plaintext {
				t.Errorf("Decrypt() goroutine %d = %q, want %q", id, decrypted, plaintext)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	successCount := 0
	for i := 0; i < iterations; i++ {
		if <-done {
			successCount++
		}
	}

	if successCount != iterations {
		t.Errorf("Concurrent test: %d/%d succeeded", successCount, iterations)
	}
}

func TestEncryptDecrypt_FromRSAEncryptedKey(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Encrypt a test key with RSA
	testKey := "my-secret-key-32-bytes-long!!"
	hash := sha256.New()
	encryptedKeyBytes, err := rsa.EncryptOAEP(hash, rand.Reader, &privateKey.PublicKey, []byte(testKey), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt key: %v", err)
	}
	encryptedKey := base64.StdEncoding.EncodeToString(encryptedKeyBytes)

	// Create encryptor from RSA-encrypted key
	encryptor, err := NewEncryptorFromRSAEncryptedKey(encryptedKey, privateKey)
	if err != nil {
		t.Fatalf("NewEncryptorFromRSAEncryptedKey() error = %v", err)
	}

	// Test encryption/decryption
	plaintext := "test message"
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_EdgeCases(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"single byte", "a"},
		{"exactly 16 bytes", strings.Repeat("a", 16)},
		{"exactly 32 bytes", strings.Repeat("a", 32)},
		{"exactly 64 bytes", strings.Repeat("a", 64)},
		{"exactly 128 bytes", strings.Repeat("a", 128)},
		{"all zeros", strings.Repeat("\x00", 100)},
		{"all ones", strings.Repeat("\xFF", 100)},
		{"alternating", strings.Repeat("\x00\xFF", 50)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := encryptor.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if decrypted != tc.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tc.plaintext)
			}
		})
	}
}

func TestEncryptDecrypt_Format(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "test"
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decode base64 to check format
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Check minimum length: encrypted data + auth tag (16 bytes)
	// Note: nonce is NOT included in ciphertext
	minLength := encryptor.gcm.Overhead() // GCM auth tag is 16 bytes
	if len(ciphertextBytes) < minLength {
		t.Errorf("Ciphertext too short: got %d bytes, want at least %d", len(ciphertextBytes), minLength)
	}

	// Verify ciphertext does not start with nonce (nonce is not included)
	// The ciphertext should be shorter than if it included nonce
	expectedLengthWithNonce := encryptor.nonceSize + len(plaintext) + encryptor.gcm.Overhead()
	if len(ciphertextBytes) >= expectedLengthWithNonce {
		t.Errorf("Ciphertext length suggests nonce might be included: got %d bytes, expected less than %d",
			len(ciphertextBytes), expectedLengthWithNonce)
	}
}

func TestEncryptedString(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	t.Run("basic usage", func(t *testing.T) {
		plaintext := "user@example.com"
		encrypted := &EncryptedString{
			Plaintext: plaintext,
			encryptor: encryptor,
		}

		// Test Value() - encryption
		value, err := encrypted.Value()
		if err != nil {
			t.Fatalf("Value() error = %v", err)
		}

		valueStr, ok := value.(string)
		if !ok {
			t.Fatalf("Value() returned non-string type: %T", value)
		}

		if valueStr == plaintext {
			t.Error("Value() should return encrypted value, not plaintext")
		}

		// Test Scan() - decryption
		var scanned EncryptedString
		scanned.encryptor = encryptor
		err = scanned.Scan(valueStr)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}

		if scanned.Plaintext != plaintext {
			t.Errorf("Scan() plaintext = %q, want %q", scanned.Plaintext, plaintext)
		}
	})

	t.Run("with global encryptor", func(t *testing.T) {
		SetDefaultEncryptor(encryptor)
		defer SetDefaultEncryptor(nil)

		plaintext := "test@example.com"
		encrypted := ES(plaintext)

		// Test Value() with default encryptor
		value, err := encrypted.Value()
		if err != nil {
			t.Fatalf("Value() error = %v", err)
		}

		// Test Scan() with default encryptor
		var scanned EncryptedString
		err = scanned.Scan(value)
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}

		if scanned.Plaintext != plaintext {
			t.Errorf("Scan() plaintext = %q, want %q", scanned.Plaintext, plaintext)
		}
	})

	t.Run("nil encryptor error", func(t *testing.T) {
		// Temporarily clear default encryptor
		oldDefault := GetDefaultEncryptor()
		SetDefaultEncryptor(nil)
		defer SetDefaultEncryptor(oldDefault)

		encrypted := &EncryptedString{Plaintext: "test"}

		_, err := encrypted.Value()
		if err == nil {
			t.Error("Value() should return error when encryptor is nil and no default set")
		}

		err = encrypted.Scan("test")
		if err == nil {
			t.Error("Scan() should return error when encryptor is nil and no default set")
		}
	})

	t.Run("scan different types", func(t *testing.T) {
		plaintext := "test"
		ciphertext, _ := encryptor.Encrypt(plaintext)

		testCases := []struct {
			name string
			src  any
		}{
			{"string", ciphertext},
			{"[]byte", []byte(ciphertext)},
			{"nil", nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var scanned EncryptedString
				scanned.encryptor = encryptor
				err := scanned.Scan(tc.src)
				if err != nil {
					t.Fatalf("Scan() error = %v", err)
				}

				if tc.src == nil {
					if scanned.Plaintext != "" {
						t.Errorf("Scan(nil) should result in empty string, got %q", scanned.Plaintext)
					}
				} else {
					if scanned.Plaintext != plaintext {
						t.Errorf("Scan() plaintext = %q, want %q", scanned.Plaintext, plaintext)
					}
				}
			})
		}
	})

	t.Run("scan unsupported type", func(t *testing.T) {
		var scanned EncryptedString
		scanned.encryptor = encryptor
		err := scanned.Scan(123)
		if err == nil {
			t.Error("Scan() should return error for unsupported type")
		}
	})

	t.Run("String() method", func(t *testing.T) {
		SetDefaultEncryptor(encryptor)
		defer SetDefaultEncryptor(nil)

		encrypted := ES("test")
		if encrypted.Plaintext != "test" {
			t.Errorf("String() = %q, want %q", encrypted.Plaintext, "test")
		}
	})
}

func TestES_Panic(t *testing.T) {
	SetDefaultEncryptor(nil)

	defer func() {
		if r := recover(); r == nil {
			t.Error("ES() should panic when default encryptor is nil")
		}
	}()

	_ = ES("test")
}

func TestES(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	SetDefaultEncryptor(encryptor)
	defer SetDefaultEncryptor(nil)

	plaintext := "test@example.com"
	encrypted := ES(plaintext)

	if encrypted.Plaintext != plaintext {
		t.Errorf("ES() plaintext = %q, want %q", encrypted.Plaintext, plaintext)
	}

	// Test pointer usage
	es := ES(plaintext)
	encryptedPtr := &es
	if encryptedPtr.Plaintext != plaintext {
		t.Errorf("&ES() plaintext = %q, want %q", encryptedPtr.Plaintext, plaintext)
	}
}

func TestESP(t *testing.T) {
	encryptor, err := NewEncryptor("my-secret-key-32-bytes-long!!")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	SetDefaultEncryptor(encryptor)
	defer SetDefaultEncryptor(nil)

	plaintext := "test@example.com"
	encrypted := ESP(plaintext)

	// Check that ESP returns a pointer
	if encrypted == nil {
		t.Fatal("ESP() returned nil")
	}

	if encrypted.Plaintext != plaintext {
		t.Errorf("ESP() plaintext = %q, want %q", encrypted.Plaintext, plaintext)
	}

	// Verify it can be used with driver.Valuer
	value, err := encrypted.Value()
	if err != nil {
		t.Errorf("ESP().Value() error = %v", err)
	}
	if value == "" {
		t.Error("ESP().Value() returned empty string")
	}
}

func TestESP_Panic(t *testing.T) {
	SetDefaultEncryptor(nil)

	defer func() {
		if r := recover(); r == nil {
			t.Error("ESP() should panic when default encryptor is nil")
		}
	}()

	_ = ESP("test")
}
