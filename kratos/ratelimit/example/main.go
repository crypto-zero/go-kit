package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crypto-zero/go-kit/kratos/ratelimit"
	redisstore "github.com/crypto-zero/go-kit/kratos/ratelimit/redis"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	createOrderOperation = "/ratelimit.example.order.v1.OrderService/CreateOrder"
	getOrderOperation    = "/ratelimit.example.order.v1.OrderService/GetOrder"
)

type config struct {
	HTTPAddr    string
	RedisAddr   string
	RedisPrefix string

	RateLimit *rateLimitConfig
}

// These config structs mirror the shape a business service would define in
// internal/conf/conf.proto and receive from Kratos config loading.
type rateLimitConfig struct {
	Operations map[string]*rateLimitOperation
}

type rateLimitOperation struct {
	Rules []*rateLimitRule
}

type rateLimitRule struct {
	KeyParts []string
	Rate     int32
	Per      *durationpb.Duration
	Burst    int32
}

func main() {
	cfg := config{
		HTTPAddr:    ":8000",
		RedisAddr:   "127.0.0.1:6379",
		RedisPrefix: "ratelimit-example:order-api",
		RateLimit: &rateLimitConfig{
			Operations: map[string]*rateLimitOperation{
				createOrderOperation: {
					Rules: []*rateLimitRule{
						{
							KeyParts: []string{"user_id"},
							Rate:     10,
							Per:      durationpb.New(time.Minute),
							Burst:    10,
						},
						{
							KeyParts: []string{"client_ip"},
							Rate:     30,
							Per:      durationpb.New(time.Minute),
							Burst:    30,
						},
					},
				},
				getOrderOperation: {
					Rules: []*rateLimitRule{
						{
							KeyParts: []string{"user_id"},
							Rate:     100,
							Per:      durationpb.New(time.Minute),
							Burst:    100,
						},
					},
				},
			},
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg config) error {
	redisClient := goredis.NewClient(&goredis.Options{Addr: cfg.RedisAddr})
	defer redisClient.Close()

	store, err := redisstore.NewStore(redisClient, cfg.RedisPrefix)
	if err != nil {
		return err
	}
	operationRules, err := convertRateLimitConfig(cfg.RateLimit)
	if err != nil {
		return err
	}
	mw, err := ratelimit.Server(
		ratelimit.WithRuleStore(store),
		ratelimit.WithOperationRules(operationRules),
		ratelimit.WithClientIPKeyFunc(ratelimit.ClientIPKey),
		ratelimit.WithUserKeyFunc(userIDFromHeader),
	)
	if err != nil {
		return err
	}
	srv := khttp.NewServer(
		khttp.Address(cfg.HTTPAddr),
		khttp.Middleware(mw),
	)
	registerOrderHTTPServer(srv)

	errc := make(chan error, 1)
	go func() { errc <- srv.Start(ctx) }()

	select {
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Stop(stopCtx)
	case err := <-errc:
		return err
	}
}

func convertRateLimitConfig(cfg *rateLimitConfig) (ratelimit.OperationRules, error) {
	if cfg == nil || len(cfg.Operations) == 0 {
		return nil, nil
	}
	rules := make(ratelimit.OperationRules, len(cfg.Operations))
	for operation, op := range cfg.Operations {
		if operation == "" {
			return nil, fmt.Errorf("rate_limit operation must not be empty")
		}
		if op == nil || len(op.Rules) == 0 {
			return nil, fmt.Errorf("%s: rate_limit rules must not be empty", operation)
		}
		for i, rule := range op.Rules {
			converted, err := convertRateLimitRule(rule)
			if err != nil {
				return nil, fmt.Errorf("%s rules[%d]: %w", operation, i, err)
			}
			rules[operation] = append(rules[operation], converted)
		}
	}
	return rules, nil
}

func convertRateLimitRule(rule *rateLimitRule) (ratelimit.RuleConfig, error) {
	if rule == nil {
		return ratelimit.RuleConfig{}, fmt.Errorf("rule must not be nil")
	}
	if rule.Rate <= 0 || rule.Per == nil || rule.Per.AsDuration() <= 0 || rule.Burst <= 0 {
		return ratelimit.RuleConfig{}, fmt.Errorf("rate, per, and burst must be explicitly positive")
	}
	keyParts, err := convertKeyParts(rule.KeyParts)
	if err != nil {
		return ratelimit.RuleConfig{}, err
	}
	return ratelimit.RuleConfig{
		Config: ratelimit.Config{
			Rate:  int(rule.Rate),
			Per:   rule.Per.AsDuration(),
			Burst: int(rule.Burst),
		},
		KeyParts: keyParts,
	}, nil
}

func convertKeyParts(parts []string) ([]ratelimit.KeyPart, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("key_parts must not be empty")
	}
	keyParts := make([]ratelimit.KeyPart, 0, len(parts))
	for _, part := range parts {
		kp, err := ratelimit.ParseKeyPart(part)
		if err != nil {
			return nil, err
		}
		keyParts = append(keyParts, kp)
	}
	return keyParts, nil
}

func userIDFromHeader(ctx context.Context, _ any) string {
	if req, ok := khttp.RequestFromServerContext(ctx); ok {
		return req.Header.Get("X-User-ID")
	}
	return ""
}

func registerOrderHTTPServer(srv *khttp.Server) {
	route := srv.Route("/")
	route.POST("/v1/orders", createOrder)
	route.GET("/v1/orders/{order_id}", getOrder)
}

func createOrder(ctx khttp.Context) error {
	khttp.SetOperation(ctx, createOrderOperation)

	req := new(createOrderRequest)
	if err := ctx.Bind(req); err != nil {
		return err
	}
	handler := ctx.Middleware(func(context.Context, any) (any, error) {
		return &createOrderResponse{
			OrderId: fmt.Sprintf("order_for_%s", req.GetSku()),
		}, nil
	})
	return ctx.Returns(handler(ctx, req))
}

func getOrder(ctx khttp.Context) error {
	khttp.SetOperation(ctx, getOrderOperation)

	req := new(getOrderRequest)
	if err := ctx.BindVars(req); err != nil {
		return err
	}
	handler := ctx.Middleware(func(context.Context, any) (any, error) {
		return &getOrderResponse{
			OrderId: req.GetOrderId(),
			Status:  "created",
		}, nil
	})
	return ctx.Returns(handler(ctx, req))
}

var _ http.Handler = (*khttp.Server)(nil)

type createOrderRequest struct {
	Sku string `json:"sku"`
}

func (r *createOrderRequest) GetSku() string {
	if r == nil {
		return ""
	}
	return r.Sku
}

type createOrderResponse struct {
	OrderId string `json:"order_id"`
}

type getOrderRequest struct {
	OrderId string `json:"order_id" form:"order_id"`
}

func (r *getOrderRequest) GetOrderId() string {
	if r == nil {
		return ""
	}
	return r.OrderId
}

type getOrderResponse struct {
	OrderId string `json:"order_id"`
	Status  string `json:"status"`
}
