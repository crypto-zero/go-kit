package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypto-zero/go-kit/kratos/ratelimit"
	goredis "github.com/redis/go-redis/v9"
)

// fakeClient implements goredis.Scripter for tests. It forces the EVALSHA
// fast-path to miss so Eval is called, which lets the test inspect the script
// body and arg layout.
type fakeClient struct {
	script string
	keys   []string
	args   []any
	cmd    *goredis.Cmd
	evals  int
}

func (f *fakeClient) Eval(_ context.Context, script string, keys []string, args ...any) *goredis.Cmd {
	f.evals++
	f.script = script
	f.keys = append([]string(nil), keys...)
	f.args = append([]any(nil), args...)
	if f.cmd != nil {
		return f.cmd
	}
	return goredis.NewCmdResult([]any{int64(1), int64(4), int64(0)}, nil)
}

func (f *fakeClient) EvalRO(ctx context.Context, script string, keys []string, args ...any) *goredis.Cmd {
	return f.Eval(ctx, script, keys, args...)
}

func (f *fakeClient) EvalSha(_ context.Context, _ string, _ []string, _ ...any) *goredis.Cmd {
	return goredis.NewCmdResult(nil, goredis.ErrNoScript)
}

func (f *fakeClient) EvalShaRO(ctx context.Context, sha1 string, keys []string, args ...any) *goredis.Cmd {
	return f.EvalSha(ctx, sha1, keys, args...)
}

func (f *fakeClient) ScriptExists(_ context.Context, _ ...string) *goredis.BoolSliceCmd {
	return goredis.NewBoolSliceResult(nil, nil)
}

func (f *fakeClient) ScriptLoad(_ context.Context, _ string) *goredis.StringCmd {
	return goredis.NewStringResult("", nil)
}

func TestStoreTakeEvaluatesScript(t *testing.T) {
	client := &fakeClient{}
	store, err := newScriptStore(client, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	res, err := store.Take(context.Background(), "tenant-1", time.UnixMilli(1000), ratelimit.Limit{
		Rate:  5,
		Per:   time.Second,
		Burst: 10,
	}, 3)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !res.Allowed || res.Remaining != 4 || res.RetryAfter != 0 {
		t.Fatalf("result = %+v, want allowed with 4 remaining", res)
	}
	if client.script != takeScript {
		t.Fatal("Eval script mismatch")
	}
	if len(client.keys) != 1 || client.keys[0] != "{tenant-1}:api:tenant-1" {
		t.Fatalf("keys = %#v, want hash-tagged api key", client.keys)
	}
	wantArgs := []any{3, 5, int64(1000), 10, int64(2000)}
	if len(client.args) != len(wantArgs) {
		t.Fatalf("args = %#v, want %#v", client.args, wantArgs)
	}
	for i := range wantArgs {
		if client.args[i] != wantArgs[i] {
			t.Fatalf("arg %d = %#v, want %#v", i, client.args[i], wantArgs[i])
		}
	}
}

func TestStoreTakeParsesRejectedResult(t *testing.T) {
	client := &fakeClient{
		cmd: goredis.NewCmdResult([]any{int64(0), int64(0), int64(500)}, nil),
	}
	store, err := newScriptStore(client, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	res, err := store.Take(context.Background(), "tenant-1", time.UnixMilli(1000), ratelimit.Limit{
		Rate:  2,
		Per:   time.Second,
		Burst: 1,
	}, 1)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if res.Allowed || res.Remaining != 0 || res.RetryAfter != 500*time.Millisecond {
		t.Fatalf("result = %+v, want rejected with 500ms retry", res)
	}
}

func TestStoreTakeManyParsesPerKeyResults(t *testing.T) {
	client := &fakeClient{
		cmd: goredis.NewCmdResult([]any{
			int64(1), int64(9), int64(0),
			int64(0), int64(0), int64(750),
		}, nil),
	}
	store, err := newScriptStore(client, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	results, err := store.TakeMany(context.Background(),
		[]string{"/svc/A:user_id:user-1", "/svc/A:client_ip:ip-1"},
		time.UnixMilli(1000),
		[]ratelimit.Limit{
			{Rate: 10, Per: time.Second, Burst: 10},
			{Rate: 2, Per: time.Second, Burst: 1},
		},
		1,
	)
	if err != nil {
		t.Fatalf("TakeMany: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if !results[0].Allowed || results[0].Remaining != 9 || results[0].RetryAfter != 0 {
		t.Fatalf("results[0] = %+v, want allowed with 9 remaining", results[0])
	}
	if results[1].Allowed || results[1].RetryAfter != 750*time.Millisecond {
		t.Fatalf("results[1] = %+v, want rejected with 750ms retry", results[1])
	}
	if len(client.keys) != 2 || client.keys[0] != "{/svc/A}:api:/svc/A:user_id:user-1" || client.keys[1] != "{/svc/A}:api:/svc/A:client_ip:ip-1" {
		t.Fatalf("keys = %#v, want shared hash tag from first key in order", client.keys)
	}
}

func TestRedisKeyUsesSanitizedGroupHashTag(t *testing.T) {
	store, err := newScriptStore(&fakeClient{}, "api{prod}")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	tag := sanitizeHashTag(keyGroup("/svc/{Order}:Create"))
	if got := store.redisKey("/svc/{Order}:Create:user_id:u1", tag); got != "{/svc/_Order_}:api{prod}:/svc/{Order}:Create:user_id:u1" {
		t.Fatalf("redisKey = %q, want sanitized group hash tag", got)
	}
}

func TestStoreTakeManyRejectsKeyLimitMismatch(t *testing.T) {
	store, err := newScriptStore(&fakeClient{}, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_, err = store.TakeMany(context.Background(),
		[]string{"a", "b"},
		time.UnixMilli(1000),
		[]ratelimit.Limit{{Rate: 1, Per: time.Second, Burst: 1}},
		1,
	)
	if !errors.Is(err, ErrKeyLimitMismatch) {
		t.Fatalf("TakeMany error = %v, want ErrKeyLimitMismatch", err)
	}

	_, err = store.TakeMany(context.Background(),
		nil,
		time.UnixMilli(1000),
		[]ratelimit.Limit{{Rate: 1, Per: time.Second, Burst: 1}},
		1,
	)
	if !errors.Is(err, ErrKeyLimitMismatch) {
		t.Fatalf("TakeMany empty keys mismatch error = %v, want ErrKeyLimitMismatch", err)
	}
}

func TestStoreTakeManyRejectsKeyGroupMismatch(t *testing.T) {
	store, err := newScriptStore(&fakeClient{}, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_, err = store.TakeMany(context.Background(),
		[]string{"/svc/A:user_id:u1", "/svc/B:client_ip:127.0.0.1"},
		time.UnixMilli(1000),
		[]ratelimit.Limit{
			{Rate: 1, Per: time.Second, Burst: 1},
			{Rate: 1, Per: time.Second, Burst: 1},
		},
		1,
	)
	if !errors.Is(err, ErrKeyGroupMismatch) {
		t.Fatalf("TakeMany error = %v, want ErrKeyGroupMismatch", err)
	}
}

func TestStoreTakeManyAllowsNonPositiveNWithoutRedis(t *testing.T) {
	client := &fakeClient{}
	store, err := newScriptStore(client, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	results, err := store.TakeMany(context.Background(),
		[]string{"tenant-1"},
		time.UnixMilli(1000),
		[]ratelimit.Limit{{Rate: 1, Per: time.Second, Burst: 1}},
		-1,
	)
	if err != nil {
		t.Fatalf("TakeMany: %v", err)
	}
	if len(results) != 1 || !results[0].Allowed {
		t.Fatalf("results = %+v, want one allowed result", results)
	}
	if client.evals != 0 {
		t.Fatalf("Eval calls = %d, want 0 for non-positive n", client.evals)
	}
}

func TestStoreTakeReturnsRedisError(t *testing.T) {
	redisErr := errors.New("redis unavailable")
	store, err := newScriptStore(&fakeClient{cmd: goredis.NewCmdResult(nil, redisErr)}, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_, err = store.Take(context.Background(), "tenant-1", time.UnixMilli(1000), ratelimit.Limit{
		Rate:  1,
		Per:   time.Second,
		Burst: 1,
	}, 1)
	if !errors.Is(err, redisErr) {
		t.Fatalf("Take error = %v, want redis error", err)
	}
}

func TestNewStoreRejectsMissingClient(t *testing.T) {
	_, err := NewStore(nil, "api")
	if !errors.Is(err, ErrMissingClient) {
		t.Fatalf("NewStore error = %v, want ErrMissingClient", err)
	}
}

func TestNewStoreRejectsMissingPrefix(t *testing.T) {
	_, err := newScriptStore(&fakeClient{}, "")
	if !errors.Is(err, ErrMissingPrefix) {
		t.Fatalf("NewStore error = %v, want ErrMissingPrefix", err)
	}
}

func TestStoreTakeRejectsMissingKey(t *testing.T) {
	store, err := newScriptStore(&fakeClient{}, "api")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_, err = store.Take(context.Background(), "", time.UnixMilli(1000), ratelimit.Limit{
		Rate:  1,
		Per:   time.Second,
		Burst: 1,
	}, 1)
	if !errors.Is(err, ratelimit.ErrMissingKey) {
		t.Fatalf("Take error = %v, want ErrMissingKey", err)
	}
}

func TestParseResultsRejectsInvalidLength(t *testing.T) {
	_, err := parseResults([]any{int64(1)}, 1)
	if !errors.Is(err, ErrInvalidScriptResult) {
		t.Fatalf("parseResults error = %v, want ErrInvalidScriptResult", err)
	}
}

func TestDurationMillisRoundsTinyDurationUp(t *testing.T) {
	if got := durationMillis(time.Nanosecond); got != 1 {
		t.Fatalf("durationMillis(time.Nanosecond) = %d, want 1", got)
	}
}

func TestTTLCoversFullRefillFromEmpty(t *testing.T) {
	got := ttl(ratelimit.Limit{Rate: 1, Per: time.Minute, Burst: 600})
	wantMin := int64(600) * time.Minute.Milliseconds() / 1 // refill-from-empty time
	if got < wantMin {
		t.Fatalf("ttl = %d ms, want >= %d ms so idle keys do not reset to burst", got, wantMin)
	}
}
