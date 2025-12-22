package encryption

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseRSAPrivateKeyFromPEM parses an RSA private key from PEM format.
func ParseRSAPrivateKeyFromPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var key any
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an RSA private key")
	}

	return rsaKey, nil
}

// ParseRSAPrivateKeyFromString parses an RSA private key from a PEM-format string.
// The string should contain a PEM-encoded RSA private key.
func ParseRSAPrivateKeyFromString(pemString string) (*rsa.PrivateKey, error) {
	return ParseRSAPrivateKeyFromPEM([]byte(pemString))
}

// ParseRSAPublicKeyFromPEM parses an RSA public key from PEM format.
func ParseRSAPublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var key any
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an RSA public key")
	}

	return rsaKey, nil
}

// ParseRSAPublicKeyFromString parses an RSA public key from a PEM-format string.
// The string should contain a PEM-encoded RSA public key.
func ParseRSAPublicKeyFromString(pemString string) (*rsa.PublicKey, error) {
	return ParseRSAPublicKeyFromPEM([]byte(pemString))
}
