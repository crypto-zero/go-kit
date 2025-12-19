package ent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// EntEncryptor provides symmetric encryption functionality using AES-GCM mode.
type EntEncryptor struct {
	key []byte
}

// NewEncryptor creates a new encryptor.
// key must be 16, 24, or 32 bytes (corresponding to AES-128, AES-192, AES-256).
func NewEncryptor(key []byte) (*EntEncryptor, error) {
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("key length must be 16, 24, or 32 bytes")
	}
	return &EntEncryptor{key: key}, nil
}

// NewEncryptorFromString creates an encryptor from a string (automatically handles key length).
func NewEncryptorFromString(key string) (*EntEncryptor, error) {
	keyBytes := []byte(key)
	keyLen := len(keyBytes)

	// If the key length doesn't meet requirements, use SHA256 hash
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		// Use SHA256 to generate a 32-byte key (AES-256)
		hash := sha256.Sum256(keyBytes)
		keyBytes = hash[:]
	}

	return &EntEncryptor{key: keyBytes}, nil
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
