# protoc-gen-go-redact

A protoc plugin that generates `Redact()` methods for Protocol Buffer messages to safely mask sensitive fields when logging or serializing data.

## Features

- Generates `Redact()` method for messages containing sensitive fields
- Customizable mask strings per field
- Returns JSON-formatted string with sensitive data replaced
- Works alongside `protoc-gen-go` as a complementary plugin

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

First, import the redact options in your `.proto` file:

```protobuf
syntax = "proto3";

package yourpackage;

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
  User user = 3;
}
```

### 3. Generate code

Run protoc with both `protoc-gen-go` and `protoc-gen-go-redact`:

```bash
protoc \
  -I. \
  -I/path/to/go-kit/proto \
  --go_out=. --go_opt=paths=source_relative \
  --go-redact_out=. --go-redact_opt=paths=source_relative \
  your_proto_file.proto
```

This generates two files:
- `your_proto_file.pb.go` - Standard protobuf Go code
- `your_proto_file_redact.pb.go` - Redact methods

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
// Output: {"age":30,"email":"***","name":"John Doe","password":"[HIDDEN]"}

// Original data remains unchanged
fmt.Println(user.Email)    // john@example.com
fmt.Println(user.Password) // secret123
```

###
```bash
protoc --plugin=./protoc-gen-go-redact -I. -I../proto --go_out=. --go_opt=paths=source_relative --go-redact_out=. --go-redact_opt=paths=source_relative testdata/example.proto
```

## Redact Options

| Field   | Type   | Default | Description                              |
|---------|--------|---------|------------------------------------------|
| `redact`| bool   | false   | Whether to redact this field             |
| `mask`  | string | `***`   | The mask string to replace the value with|

## Generated Method

For each message with at least one redacted field, a `Redact()` method is generated:

```go
// Redact returns a redacted JSON string representation of User.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
func (x *User) Redact() string {
    if x == nil {
        return "{}"
    }
    m := make(map[string]any)
    m["name"] = x.Name
    m["email"] = "***"
    m["password"] = "[HIDDEN]"
    m["age"] = x.Age
    b, _ := json.Marshal(m)
    return string(b)
}
```

## Use Cases

- **Logging**: Safely log request/response data without exposing sensitive information
- **Debugging**: Print message contents during development without leaking secrets
- **Audit trails**: Store redacted versions of data for compliance

## Example

See the [testdata](./testdata/) directory for a complete example:

- [example.proto](./testdata/example.proto) - Proto definition with redact options
- [example_redact.pb.go](./testdata/example_redact.pb.go) - Generated redact methods

## License

MIT License

