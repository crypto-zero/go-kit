package ent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

var defaultEntEncryptor *EntEncryptor

func GetDefaultEncryptor() *EntEncryptor {
	return defaultEntEncryptor
}

func SetDefaultEncryptor(encryptor *EntEncryptor) {
	defaultEntEncryptor = encryptor
}

// EntEncryptor provides symmetric encryption functionality using AES-GCM mode.
type EntEncryptor struct {
	key []byte
}

// NewEncryptor creates an encryptor from a string (automatically handles key length).
func NewEncryptor(plaintext string) (*EntEncryptor, error) {
	keyBytes := []byte(plaintext)
	keyLen := len(keyBytes)

	// If the key length doesn't meet requirements, use SHA256 hash
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		// Use SHA256 to generate a 32-byte key (AES-256)
		hash := sha256.Sum256(keyBytes)
		keyBytes = hash[:]
	}

	return &EntEncryptor{key: keyBytes}, nil
}

// NewEncryptorFromED25519EncryptedKey creates an encryptor from an ED25519-encrypted key ciphertext.
// The encrypted key (ciphertext) will be decrypted using the ED25519 private key,
// then used as the AES encryption key.
// encryptedKey: base64-encoded ciphertext of the key encrypted with ED25519 public key
// privateKey: ED25519 private key used to decrypt the encrypted key
func NewEncryptorFromED25519EncryptedKey(encryptedKey string, privateKey ed25519.PrivateKey) (*EntEncryptor, error) {
	if encryptedKey == "" {
		return nil, errors.New("encrypted key cannot be empty")
	}

	// Decode base64 encrypted key
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Extract the public key from the private key
	// Use the same key derivation as encryption (using public key)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Derive decryption key from ED25519 public key using SHA256
	// This matches the encryption key derivation
	derivedKey := sha256.Sum256(publicKey)

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedBytes) < nonceSize {
		return nil, errors.New("encrypted key too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := encryptedBytes[:nonceSize], encryptedBytes[nonceSize:]

	// Decrypt the key
	decryptedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Validate and use the decrypted key
	return NewEncryptor(string(decryptedKey))
}

// Encrypt encrypts a string deterministically and returns base64-encoded ciphertext.
// The same plaintext with the same key will always produce the same ciphertext,
// which allows for JOIN operations on encrypted fields in databases.
func (e *EntEncryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	// Use GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Derive nonce from key and plaintext using HMAC-SHA256
	// This ensures the same plaintext always produces the same nonce
	nonceSize := gcm.NonceSize()
	mac := hmac.New(sha256.New, e.key)
	mac.Write([]byte(plaintext))
	nonce := mac.Sum(nil)[:nonceSize]

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return base64-encoded ciphertext
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext and returns plaintext.
func (e *EntEncryptor) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	// Use GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
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
		return "", err
	}

	return string(plaintext), nil
}
