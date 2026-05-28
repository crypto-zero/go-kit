// Package redis provides a Redis-backed ratelimit store.
package redis

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/crypto-zero/go-kit/kratos/ratelimit"
	goredis "github.com/redis/go-redis/v9"
)

const (
	minBucketTTLMillis = 1000
	scriptArgsPerKey   = 4
	scriptResultWidth  = 3
)

var (
	// ErrMissingClient reports a store constructed without a Redis client.
	ErrMissingClient = errors.New("redis ratelimit: missing client")
	// ErrMissingPrefix reports a store constructed without an explicit Redis key prefix.
	ErrMissingPrefix = errors.New("redis ratelimit: missing prefix")
	// ErrInvalidScriptResult reports an unexpected Lua script return value.
	ErrInvalidScriptResult = errors.New("redis ratelimit: invalid script result")
	// ErrKeyLimitMismatch reports a TakeMany call with mismatched keys/limits.
	ErrKeyLimitMismatch = errors.New("redis ratelimit: keys and limits length mismatch")
	// ErrKeyGroupMismatch reports keys that cannot be evaluated in one Redis slot.
	ErrKeyGroupMismatch = errors.New("redis ratelimit: keys must share a group")
)

// Store persists rate-limit buckets in Redis.
//
// The script uses Redis-side TIME, so it tolerates client clock skew across
// multiple Kratos instances. It performs a two-phase check-and-commit across
// every key so multi-rule operations consume tokens atomically or not at all.
type Store struct {
	client goredis.Scripter
	prefix string
	script *goredis.Script
}

// NewStore constructs a Redis-backed store.
func NewStore(client goredis.UniversalClient, prefix string) (*Store, error) {
	return newScriptStore(client, prefix)
}

func newScriptStore(client goredis.Scripter, prefix string) (*Store, error) {
	if client == nil {
		return nil, ErrMissingClient
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, ErrMissingPrefix
	}
	return &Store{
		client: client,
		prefix: prefix,
		script: goredis.NewScript(takeScript),
	}, nil
}

// Take consumes n tokens from key if capacity is available.
func (s *Store) Take(ctx context.Context, key string, now time.Time, limit ratelimit.Limit, n int) (ratelimit.Result, error) {
	results, err := s.TakeMany(ctx, []string{key}, now, []ratelimit.Limit{limit}, n)
	if err != nil {
		return ratelimit.Result{}, err
	}
	return results[0], nil
}

// TakeMany consumes n tokens from every key atomically: either all keys
// commit, or none do. Order of returned Results matches input order.
//
// The now argument is ignored — the script uses Redis-side TIME.
func (s *Store) TakeMany(ctx context.Context, keys []string, _ time.Time, limits []ratelimit.Limit, n int) ([]ratelimit.Result, error) {
	if err := s.validateTake(keys, limits, n); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	if n <= 0 {
		return allowedResults(len(keys)), nil
	}

	redisKeys, args, err := s.buildScriptCall(keys, limits, n)
	if err != nil {
		return nil, err
	}
	values, err := s.script.Run(ctx, s.client, redisKeys, args...).Slice()
	if err != nil {
		return nil, err
	}
	return parseResults(values, len(keys))
}

func (s *Store) validateTake(keys []string, limits []ratelimit.Limit, n int) error {
	if s == nil || s.client == nil {
		return ErrMissingClient
	}
	if s.prefix == "" {
		return ErrMissingPrefix
	}
	if len(keys) != len(limits) {
		return ErrKeyLimitMismatch
	}
	if n <= 0 {
		return nil
	}
	for i, key := range keys {
		if key == "" {
			return ratelimit.ErrMissingKey
		}
		if err := limits[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

func allowedResults(n int) []ratelimit.Result {
	results := make([]ratelimit.Result, n)
	for i := range results {
		results[i] = ratelimit.Result{Allowed: true}
	}
	return results
}

func (s *Store) buildScriptCall(keys []string, limits []ratelimit.Limit, n int) ([]string, []any, error) {
	slotTag, err := sharedSlotTag(keys)
	if err != nil {
		return nil, nil, err
	}
	redisKeys := make([]string, len(keys))
	args := make([]any, 0, 1+len(limits)*scriptArgsPerKey)
	args = append(args, n)
	for i, key := range keys {
		redisKeys[i] = s.redisKey(key, slotTag)
		args = appendLimitArgs(args, limits[i])
	}
	return redisKeys, args, nil
}

func sharedSlotTag(keys []string) (string, error) {
	group := keyGroup(keys[0])
	for _, key := range keys[1:] {
		if keyGroup(key) != group {
			return "", ErrKeyGroupMismatch
		}
	}
	return sanitizeHashTag(group), nil
}

func (s *Store) redisKey(key, slotTag string) string {
	return "{" + slotTag + "}:" + s.prefix + ":" + key
}

func keyGroup(key string) string {
	group, _, ok := strings.Cut(key, ":")
	if ok && group != "" {
		return group
	}
	return key
}

func sanitizeHashTag(tag string) string {
	return strings.NewReplacer("{", "_", "}", "_").Replace(tag)
}

func appendLimitArgs(args []any, limit ratelimit.Limit) []any {
	return append(args,
		limit.Rate,
		durationMillis(limit.Per),
		limit.Burst,
		ttl(limit),
	)
}

func parseResults(values []any, want int) ([]ratelimit.Result, error) {
	if len(values) != want*scriptResultWidth {
		return nil, fmt.Errorf("%w: got %d values, want %d", ErrInvalidScriptResult, len(values), want*scriptResultWidth)
	}
	results := make([]ratelimit.Result, want)
	for i := 0; i < want; i++ {
		res, err := parseResult(values[i*scriptResultWidth : (i+1)*scriptResultWidth])
		if err != nil {
			return nil, err
		}
		results[i] = res
	}
	return results, nil
}

func parseResult(values []any) (ratelimit.Result, error) {
	allowed, err := int64Value(values[0])
	if err != nil {
		return ratelimit.Result{}, err
	}
	remaining, err := int64Value(values[1])
	if err != nil {
		return ratelimit.Result{}, err
	}
	retryMillis, err := int64Value(values[2])
	if err != nil {
		return ratelimit.Result{}, err
	}
	return ratelimit.Result{
		Allowed:    allowed == 1,
		Remaining:  int(remaining),
		RetryAfter: time.Duration(retryMillis) * time.Millisecond,
	}, nil
}

func int64Value(v any) (int64, error) {
	switch v := v.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %q", ErrInvalidScriptResult, v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("%w: %T", ErrInvalidScriptResult, v)
	}
}

// ttl returns the bucket's PEXPIRE in milliseconds. The bucket must outlive a
// full refill from empty so idle keys don't reset to burst and bypass the
// in-progress retry-after. A 1s floor avoids degenerate sub-second TTLs.
func ttl(limit ratelimit.Limit) int64 {
	perMs := durationMillis(limit.Per)
	refillFullMs := int64(math.Ceil(float64(limit.Burst) * float64(perMs) / float64(limit.Rate)))
	expireMillis := 2 * perMs
	if refillFullMs > expireMillis {
		expireMillis = refillFullMs
	}
	if expireMillis < minBucketTTLMillis {
		expireMillis = minBucketTTLMillis
	}
	return expireMillis
}

func durationMillis(d time.Duration) int64 {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

// takeScript drives one two-phase token consumption across N keys.
//
// ARGV layout: ARGV[1] = n; then 4 args per key starting at ARGV[2]:
// rate, per_ms, burst, ttl_ms. KEYS[i] pairs with ARGV[2+(i-1)*4 .. +3].
//
// Phase 1 refills every bucket from its stored state and snapshots the tokens.
// Phase 2 checks whether every key has capacity. Phase 3 commits the refilled
// state (and the n-token decrement only when every key passed), then emits
// three values per key: allowed (0|1), floor(remaining_tokens), retry_after_ms.
const takeScript = `
local n = tonumber(ARGV[1])
local count = #KEYS

local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)

local snap = {}
for i = 1, count do
    local base = 2 + (i - 1) * 4
    local rate = tonumber(ARGV[base])
    local per = tonumber(ARGV[base + 1])
    local burst = tonumber(ARGV[base + 2])
    local ttl = tonumber(ARGV[base + 3])

    local bucket = redis.call("HMGET", KEYS[i], "tokens", "seen")
    local tokens = tonumber(bucket[1])
    local seen = tonumber(bucket[2])
    if tokens == nil or seen == nil then
        tokens = burst
        seen = now
    else
        local elapsed = now - seen
        if elapsed > 0 then
            tokens = math.min(burst, tokens + (elapsed * rate / per))
            seen = now
        end
    end

    snap[i] = {tokens = tokens, seen = seen, rate = rate, per = per, burst = burst, ttl = ttl}
end

local allow = true
for i = 1, count do
    local s = snap[i]
    if n > s.burst or s.tokens < n then
        allow = false
        break
    end
end

local out = {}
for i = 1, count do
    local s = snap[i]
    local committed = s.tokens
    if allow then
        committed = s.tokens - n
    end
    redis.call("HSET", KEYS[i], "tokens", committed, "seen", s.seen)
    redis.call("PEXPIRE", KEYS[i], s.ttl)

    if allow then
        table.insert(out, 1)
        table.insert(out, math.floor(committed))
        table.insert(out, 0)
    else
        local retry
        if n > s.burst then
            retry = math.ceil((n - s.burst) * s.per / s.rate)
        elseif s.tokens < n then
            retry = math.ceil((n - s.tokens) * s.per / s.rate)
        else
            retry = 0
        end
        table.insert(out, 0)
        table.insert(out, math.floor(committed))
        table.insert(out, retry)
    end
end
return out
`
