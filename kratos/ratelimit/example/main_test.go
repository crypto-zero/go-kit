package main

import (
	"testing"
	"time"

	"github.com/crypto-zero/go-kit/kratos/ratelimit"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestConvertRateLimitConfig(t *testing.T) {
	rules, err := convertRateLimitConfig(&rateLimitConfig{
		Operations: map[string]*rateLimitOperation{
			createOrderOperation: {
				Rules: []*rateLimitRule{
					{
						KeyParts: []string{"user_id", "client_ip"},
						Rate:     10,
						Per:      durationpb.New(time.Minute),
						Burst:    20,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("convertRateLimitConfig error = %v, want nil", err)
	}
	if got := len(rules[createOrderOperation]); got != 1 {
		t.Fatalf("len(rules[%q]) = %d, want 1", createOrderOperation, got)
	}
	rule := rules[createOrderOperation][0]
	if rule.Config.Rate != 10 || rule.Config.Per != time.Minute || rule.Config.Burst != 20 {
		t.Fatalf("rule.Config = %+v, want rate 10 per 1m burst 20", rule.Config)
	}
	wantKeyParts := []ratelimit.KeyPart{ratelimit.KeyPartUserID, ratelimit.KeyPartClientIP}
	for i, want := range wantKeyParts {
		if rule.KeyParts[i] != want {
			t.Fatalf("rule.KeyParts[%d] = %q, want %q", i, rule.KeyParts[i], want)
		}
	}
}

func TestConvertRateLimitConfigRejectsUnknownKeyPart(t *testing.T) {
	_, err := convertRateLimitConfig(&rateLimitConfig{
		Operations: map[string]*rateLimitOperation{
			createOrderOperation: {
				Rules: []*rateLimitRule{
					{
						KeyParts: []string{"device_id"},
						Rate:     10,
						Per:      durationpb.New(time.Minute),
						Burst:    20,
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("convertRateLimitConfig error = nil, want error")
	}
}
