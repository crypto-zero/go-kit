# protoc-gen-go-redact

A protoc plugin that generates `Redact()` methods for Protocol Buffer messages to safely mask sensitive fields when logging or serializing data.

## Features

- Generates `Redact()` method for messages containing sensitive fields
- **Type-aware masking** - different types get appropriate mask values
- **Recursive redaction** - nested messages are automatically redacted
- **Full proto3 type support** - all scalar types, enums, messages, repeated, map, oneof
- **Well-known types support** - `Timestamp`, `Duration` etc. are properly formatted
- **Kratos compatible** - implements the `Redacter` interface for Kratos logging middleware
- Returns clean JSON without escape characters

## Installation

```bash
go install github.com/crypto-zero/go-kit/logging/protoc-gen-go-redact@latest
```

Or build from source:

```bash
cd logging/protoc-gen-go-redact
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
  string password = 3 [(kit.redact.v1.redact) = {redact: true, string_mask: "[HIDDEN]"}];
  int64 salary = 4 [(kit.redact.v1.redact) = {redact: true}];  // → 0
  bool is_admin = 5 [(kit.redact.v1.redact) = {redact: true}]; // → false
}

message Account {
  string id = 1;
  string secret_key = 2 [(kit.redact.v1.redact) = {redact: true, string_mask: "***SECRET***"}];
  User user = 3;  // Nested message - will be recursively redacted
  User secret_user = 4 [(kit.redact.v1.redact) = {redact: true}];  // → null
  repeated string tokens = 5 [(kit.redact.v1.redact) = {redact: true}];  // → []
  map<string, string> secrets = 6 [(kit.redact.v1.redact) = {redact: true}];  // → {}
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
    Salary:   100000,
    IsAdmin:  true,
}

// Safe for logging - sensitive data is masked
fmt.Println(user.Redact())
// Output: {"name":"John Doe","email":"*","password":"[HIDDEN]","salary":0,"isAdmin":false}

// Original data remains unchanged
fmt.Println(user.Email)    // john@example.com
fmt.Println(user.Password) // secret123
```

## Type-Aware Masking

**Scalar types** support custom mask values. **Composite types** always use default values:

| Field Type | Default Mask | Custom Mask |
|------------|--------------|-------------|
| `string` | `"*"` | ✅ `string_mask: "xxx"` |
| `bytes` | `""` (empty) | ✅ `bytes_mask: "xxx"` |
| `enum` | `0` | ✅ `enum_mask: 1` |
| `int32/int64/uint32/uint64` | `0` | ✅ `int_mask: -1` |
| `sint32/sint64` | `0` | ✅ `int_mask: -1` |
| `fixed32/fixed64/sfixed32/sfixed64` | `0` | ✅ `int_mask: -1` |
| `float/double` | `0` | ✅ `double_mask: -999.99` |
| `bool` | `false` | ✅ `bool_mask: true` |
| `message` | `null` | ❌ Default only |
| `repeated T` | `[]` | ❌ Default only |
| `map<K, V>` | `{}` | ❌ Default only |

### Custom Mask Examples

```protobuf
message Example {
  // String with custom mask
  string password = 1 [(kit.redact.v1.redact) = {redact: true, string_mask: "[HIDDEN]"}];
  
  // Integer with custom mask (-1 indicates redacted)
  int64 salary = 2 [(kit.redact.v1.redact) = {redact: true, int_mask: -1}];
  
  // Float with custom mask
  double balance = 3 [(kit.redact.v1.redact) = {redact: true, double_mask: -999.99}];
  
  // Bool with custom mask
  bool is_admin = 4 [(kit.redact.v1.redact) = {redact: true, bool_mask: false}];
  
  // Enum with custom mask (use enum value number)
  Status status = 5 [(kit.redact.v1.redact) = {redact: true, enum_mask: 0}];
  
  // Bytes with custom mask (base64 string)
  bytes secret = 6 [(kit.redact.v1.redact) = {redact: true, bytes_mask: "[REDACTED]"}];
}
```

## Redact Options

| Field   | Type   | Default | Description                              |
|---------|--------|---------|------------------------------------------|
| `redact`| bool   | false   | Whether to redact this field             |
| `string_mask` | string | `*` | Custom mask for string fields |
| `int_mask` | int64 | `0` | Custom mask for all integer types |
| `double_mask` | double | `0` | Custom mask for float/double types |
| `bool_mask` | bool | `false` | Custom mask for bool fields |
| `bytes_mask` | string | `""` | Custom mask for bytes fields |
| `enum_mask` | int32 | `0` | Custom mask for enum fields |

> **Note:** These mask options are mutually exclusive (oneof). Use the appropriate one based on your field type.

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
// Output: {"id":"acc-123","secretKey":"***SECRET***","user":{"email":"*","name":"John","password":"[HIDDEN]"}}
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

### Map Type Support

Map fields are fully supported with proper key conversion:

```go
message Config {
  map<string, string> settings = 1;
  map<string, User> users = 2;      // Message values are recursively redacted
  map<int32, string> indexed = 3;   // Non-string keys are converted to string
  map<string, string> secrets = 4 [(kit.redact.v1.redact) = {redact: true}];  // → {}
}
```

### Oneof Type Support

Oneof fields work as expected - only the set field is included in output:

```go
message Request {
  string id = 1;
  oneof credential {
    string api_key = 2 [(kit.redact.v1.redact) = {redact: true}];
    string token = 3 [(kit.redact.v1.redact) = {redact: true}];
  }
}
```

### Kratos Integration

The generated `Redact()` method implements the Kratos `Redacter` interface:

```go
// In Kratos logging middleware, your messages are automatically redacted
type Redacter interface {
    Redact() string
}
```

Use with the logging middleware:

```go
import "github.com/crypto-zero/go-kit/logging/kratos"

// Server middleware
srv := http.NewServer(
    http.Middleware(
        logging.Server(logger),
    ),
)
```

## Complete Type Coverage

The plugin supports all proto3 types:

| Category | Types |
|----------|-------|
| **Integer** | int32, int64, uint32, uint64, sint32, sint64 |
| **Fixed Integer** | fixed32, fixed64, sfixed32, sfixed64 |
| **Floating Point** | float, double |
| **Boolean** | bool |
| **String/Bytes** | string, bytes |
| **Enum** | All enum types |
| **Message** | All message types including well-known types |
| **Repeated** | repeated T (any type) |
| **Map** | map<K, V> (any key/value types) |
| **Oneof** | All oneof fields |

## Example

See the [testdata](./testdata/) directory for complete examples:

- [example.proto](./testdata/example.proto) - Proto definition with all type coverage
- [example_redact.pb.go](./testdata/example_redact.pb.go) - Generated redact methods

## License

MIT License
