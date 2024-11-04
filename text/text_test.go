package text

import (
	"strings"
	"testing"
)

func removeAdjacentDuplicates(s string) string {
	var result strings.Builder
	lastChar := ' '
	for _, c := range s {
		if c != lastChar {
			result.WriteRune(c)
			lastChar = c
		}
	}
	return result.String()
}

func TestRandString(t *testing.T) {
	siz := 10
	result := RandString(siz)
	if len(result) != siz {
		t.Fatal("RandString result length is not equal to required size")
	}
	result = removeAdjacentDuplicates(result)
	if len(result) < 2 {
		t.Fatal("RandString result unique adjacent chars is too short")
	}
}
