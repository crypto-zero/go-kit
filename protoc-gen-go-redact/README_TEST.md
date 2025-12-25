# protoc-gen-go-redact Tests

## Overview

This document describes the test suite for the `protoc-gen-go-redact` plugin.

## Test Structure

### Unit Tests

1. **template_test.go**
   - Tests template execution with various message configurations
   - Tests field redaction logic
   - Tests custom mask values
   - Coverage: Template rendering and field processing

2. **version_test.go**
   - Tests version constant format
   - Ensures version follows semantic versioning

3. **redact_test.go**
   - Tests constants (extension numbers, import paths)
   - Tests protoc version formatting
   - Placeholder for integration tests

### Test Data

- **testdata/example.proto**: Example proto file demonstrating redact options

## Running Tests

### Run All Tests

```bash
go test -v
```

### Run Specific Test

```bash
go test -v -run TestMessageDesc_Execute
```

### Run with Coverage

```bash
go test -cover
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Run with Race Detector

```bash
go test -race
```

## Test Coverage

Current test coverage focuses on:
- ✅ Template execution and rendering
- ✅ Field descriptor configuration
- ✅ Version format validation
- ✅ Constant values
- ⏳ Integration tests (requires proto file compilation setup)

## Adding New Tests

When adding new functionality:

1. Add unit tests for new functions in appropriate `*_test.go` files
2. Update example proto files in `testdata/` if needed
3. Run `go test -cover` to ensure coverage doesn't decrease
4. Document any new test requirements in this README

## Integration Testing

Full integration tests require:
- `protoc` compiler installed
- Proto files with redact extensions
- Generated code comparison

For manual integration testing:

```bash
# Build the plugin
go build -o protoc-gen-go-redact

# Use with protoc (example)
protoc --plugin=./protoc-gen-go-redact \
       --go-redact_out=. \
       testdata/example.proto
```

## Continuous Integration

Tests should be run in CI/CD pipeline with:
- Multiple Go versions (1.22+)
- Different operating systems (Linux, macOS, Windows)
- Race detector enabled
- Coverage reporting

