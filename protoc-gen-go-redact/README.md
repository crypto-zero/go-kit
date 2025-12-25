# protoc-gen-go-redact

A protoc plugin that generates `Redact()` methods for Protocol Buffer messages to safely mask sensitive fields when logging or serializing data.

## Features

- Generates `Redact()` method for messages containing sensitive fields
- Customizable mask strings per field
- **Recursive redaction** - nested messages are automatically redacted
- **Well-known types support** - `Timestamp`, `Duration` etc. are properly formatted
- **Kratos compatible** - implements the `Redacter` interface for Kratos logging middleware
- Returns clean JSON without escape characters

## Installation

```bash
go install github.com/crypto-zero/go-kit/protoc-gen-go-redact@latest
```

Or build from source:

```bash
cd protoc-gen-go-redact
go build -o protoc-gen-go-redact .
```

## Usage

### 1. Import the redact proto definition

```protobuf
syntax = "proto3";

package yourpackage;

import "google/protobuf/timestamp.proto";
import "kit/redact/v1/redact.proto";

option go_package = "your/go/package";
```

### 2. Mark sensitive fields

Use the `(kit.redact.v1.redact)` option to mark fields that should be redacted:

```protobuf
message User {
  string name = 1;
  string email = 2 [(kit.redact.v1.redact) = {redact: true}];
  string password = 3 [(kit.redact.v1.redact) = {redact: true, mask: "[HIDDEN]"}];
  int64 age = 4;
}

message Account {
  string id = 1;
  string secret_key = 2 [(kit.redact.v1.redact) = {redact: true, mask: "***SECRET***"}];
  User user = 3;  // Nested message - will be recursively redacted
}

message Event {
  string name = 1;
  string api_key = 2 [(kit.redact.v1.redact) = {redact: true}];
  google.protobuf.Timestamp created_at = 3;  // Well-known type - formatted as RFC 3339
}
```

### 3. Generate code

```bash
protoc \
  -I. \
  -I/path/to/go-kit/proto \
  --go_out=. --go_opt=paths=source_relative \
  --go-redact_out=. --go-redact_opt=paths=source_relative \
  your_proto_file.proto
```

### 4. Use in your code

```go
user := &User{
    Name:     "John Doe",
    Email:    "john@example.com",
    Password: "secret123",
    Age:      30,
}

// Safe for logging - sensitive data is masked
fmt.Println(user.Redact())
// Output: {"age":30,"email":"*","name":"John Doe","password":"[HIDDEN]"}

// Original data remains unchanged
fmt.Println(user.Email)    // john@example.com
fmt.Println(user.Password) // secret123
```

## Redact Options

| Field   | Type   | Default | Description                              |
|---------|--------|---------|------------------------------------------|
| `redact`| bool   | false   | Whether to redact this field             |
| `mask`  | string | `*`     | The mask string to replace the value with|

## Features in Detail

### Recursive Redaction

When you call `Account.Redact()`, nested messages like `User` are automatically redacted:

```go
account := &Account{
    Id:        "acc-123",
    SecretKey: "super-secret",
    User: &User{
        Name:     "John",
        Email:    "john@example.com",
        Password: "secret",
    },
}

fmt.Println(account.Redact())
// Output: {"id":"acc-123","secretKey":"***SECRET***","user":{"age":0,"email":"*","name":"John","password":"[HIDDEN]"}}
```

### Well-Known Types Support

`google.protobuf.Timestamp` and other well-known types are properly formatted:

```go
event := &Event{
    Name:      "UserLogin",
    ApiKey:    "secret-key",
    CreatedAt: timestamppb.Now(),
}

fmt.Println(event.Redact())
// Output: {"apiKey":"*","createdAt":"2024-12-25T16:00:00Z","name":"UserLogin"}
```

### Kratos Integration

The generated `Redact()` method implements the Kratos `Redacter` interface:

```go
// In Kratos logging middleware, your messages are automatically redacted
type Redacter interface {
    Redact() string
}
```

## Example

See the [testdata](./testdata/) directory for complete examples:

- [example.proto](./testdata/example.proto) - Proto definition with redact options
- [example_redact.pb.go](./testdata/example_redact.pb.go) - Generated redact methods

## License

MIT License
