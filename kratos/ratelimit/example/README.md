# Kratos Rate Limit Example

This example shows operation-level rate limiting driven only by external config.

Kratos already provides the current operation name at request time. The
middleware uses that operation as the namespace, then applies the configured
business key parts:

- `CreateOrder`: limit by `user_id`, and separately by `client_ip`
- `GetOrder`: limit by `user_id`

In a real Kratos service, define this config shape in that service's own
`internal/conf/conf.proto`, then load it from YAML and convert it to
`ratelimit.OperationRules`. The config proto should live with the service
because operations and business dimensions are service-owned.

```proto
message Bootstrap {
  Server server = 1;
  Data data = 2;
  RateLimit rate_limit = 3;
}

message RateLimit {
  map<string, Operation> operations = 1;

  message Operation {
    repeated Rule rules = 1;
  }

  message Rule {
    repeated string key_parts = 1;
    int32 rate = 2;
    google.protobuf.Duration per = 3;
    int32 burst = 4;
  }
}
```

```yaml
rate_limit:
  operations:
    /ratelimit.example.order.v1.OrderService/CreateOrder:
      rules:
        - key_parts: [user_id]
          rate: 10
          per: 60s
          burst: 10
        - key_parts: [client_ip]
          rate: 30
          per: 60s
          burst: 30
    /ratelimit.example.order.v1.OrderService/GetOrder:
      rules:
        - key_parts: [user_id]
          rate: 100
          per: 60s
          burst: 100
```

Convert the generated service config before wiring the middleware:

```go
operationRules, err := convertRateLimitConfig(conf.RateLimit)
if err != nil {
	return err
}
```

The server wires external rules into the middleware:

```go
mw, err := ratelimit.Server(
	ratelimit.WithRuleStore(store),
	ratelimit.WithOperationRules(operationRules),
	ratelimit.WithClientIPKeyFunc(ratelimit.ClientIPKey),
	ratelimit.WithUserKeyFunc(userIDFromHeader),
)
if err != nil {
	return err
}
```

Run Redis locally, then start the example:

```bash
go run ./kratos/ratelimit/example
```

Try the limited endpoints:

```bash
curl -H 'X-User-ID: user_123' \
  -H 'X-Real-IP: 127.0.0.1' \
  -H 'Content-Type: application/json' \
  -d '{"sku":"book"}' \
  http://127.0.0.1:8000/v1/orders

curl -H 'X-User-ID: user_123' \
  http://127.0.0.1:8000/v1/orders/order_for_book
```
