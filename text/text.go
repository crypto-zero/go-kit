package text

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"os"
	"strings"
	"unicode"

	"golang.org/x/text/width"
)

// GeneratePassword generate password from /dev/urandom.
func GeneratePassword(size int, accept func(byte) bool) (string, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return "", fmt.Errorf("open /dev/urandom: %w", err)
	}
	password := make([]byte, 0, size)
	for len(password) < size {
		buf := make([]byte, size*2)
		n, err := f.Read(buf)
		if err != nil {
			return "", fmt.Errorf("read /dev/urandom: %w", err)
		}
		for idx := 0; idx < n; idx++ {
			// Ascii printable characters
			if accept(buf[idx]) && len(password) < size {
				password = append(password, buf[idx])
			}
		}
	}
	return string(password), nil
}

// GeneratePasswordLitterNumbers generate password with litter and numbers.
func GeneratePasswordLitterNumbers(size int) (string, error) {
	return GeneratePassword(size, func(b byte) bool {
		return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
	})
}

// SaltSha256512 returns a salted sha256 and sha512 hex string.
func SaltSha256512(in, salt string) string {
	in = fmt.Sprintf("%s%s%s", salt, in, salt)
	rs := sha256.Sum256([]byte(in))
	nrs := sha512.Sum384(rs[:])
	return hex.EncodeToString(nrs[:])
}

// RandString returns a random string with given length.
func RandString(length int) string {
	const charset = "ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789"
	return RandStringWithCharset(length, charset)
}

// maxInt64 is the maximum value of int64.
var maxInt64 = big.NewInt(math.MaxInt64)

// RandStringWithCharset returns a random string with given length and charset.
// it uses crypto/rand to generate random string.
func RandStringWithCharset(length int, charset string) string {
	var seed int64
	if err := binary.Read(crand.Reader, binary.BigEndian, &seed); err != nil {
		seed = mrand.Int63()
	}

	siz := uint64(len(charset))
	sizBig := big.NewInt(int64(siz))
	r := mrand.New(mrand.NewSource(seed))

	b := make([]byte, length)
	for i := range b {
		rd := r.Uint64()
		if rdBig, err := crand.Int(crand.Reader, maxInt64); err == nil {
			rs := big.Int{}
			rs.Mod(rdBig, sizBig)
			rd = rs.Uint64()
		}
		b[i] = charset[rd%siz]
	}
	return string(b)
}

// CleanAllSpace returns a string with all space characters removed.
func CleanAllSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// NarrowString 全角转半角
func NarrowString(s string) string {
	return width.Narrow.String(s)
}

// CleanString clean all space and narrow string
func CleanString(s string) string {
	return CleanAllSpace(NarrowString(strings.ToValidUTF8(s, "")))
}

// TrimString trim prefix and suffix space and narrow string
func TrimString(s string) string {
	return strings.TrimSpace(NarrowString(strings.ToValidUTF8(s, "")))
}
