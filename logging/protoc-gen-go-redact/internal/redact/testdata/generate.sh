#!/bin/bash
# generate.sh - Generate all test proto files for protoc-gen-go-redact
set -e

cd "$(dirname "$0")"

echo "=========================================="
echo "protoc-gen-go-redact Code Generator"
echo "=========================================="

echo ""
echo "1. Building plugin..."
(cd ../../.. && go build -o protoc-gen-go-redact .)
if [ ! -f "../../../protoc-gen-go-redact" ]; then
    echo "ERROR: Plugin build failed!"
    exit 1
fi
echo "   ✓ Plugin built successfully"

echo ""
echo "2. Generating example.proto..."
protoc \
    --proto_path=../../../../../proto \
    --proto_path=. \
    --go_out=. --go_opt=paths=source_relative \
    example.proto

protoc \
    --proto_path=../../../../../proto \
    --proto_path=. \
    --plugin=protoc-gen-go-redact=../../../protoc-gen-go-redact \
    --go-redact_out=. --go-redact_opt=paths=source_relative \
    example.proto

if [ ! -f "example.pb.go" ] || [ ! -f "example_redact.pb.go" ]; then
    echo "ERROR: example files not generated!"
    exit 1
fi
echo "   ✓ example.pb.go"
echo "   ✓ example_redact.pb.go"

echo ""
echo "3. Generating crossfile/*.proto (cross-file propagation test)..."
# Key: Both files must be passed to protoc together for cross-file propagation
protoc \
    --proto_path=../../../../../proto \
    --proto_path=. \
    --go_out=. --go_opt=paths=source_relative \
    crossfile/sensitive.proto \
    crossfile/container.proto

protoc \
    --proto_path=../../../../../proto \
    --proto_path=. \
    --plugin=protoc-gen-go-redact=../../../protoc-gen-go-redact \
    --go-redact_out=. --go-redact_opt=paths=source_relative \
    crossfile/sensitive.proto \
    crossfile/container.proto

if [ ! -f "crossfile/sensitive.pb.go" ] || [ ! -f "crossfile/sensitive_redact.pb.go" ]; then
    echo "ERROR: sensitive files not generated!"
    exit 1
fi
echo "   ✓ crossfile/sensitive.pb.go"
echo "   ✓ crossfile/sensitive_redact.pb.go"

# Critical test: container.proto has NO direct redact fields,
# but should get Redact() via cross-file propagation
if [ ! -f "crossfile/container.pb.go" ] || [ ! -f "crossfile/container_redact.pb.go" ]; then
    echo "ERROR: container files not generated!"
    echo "Cross-file propagation may have FAILED."
    exit 1
fi
echo "   ✓ crossfile/container.pb.go"
echo "   ✓ crossfile/container_redact.pb.go (CROSS-FILE PROPAGATION WORKS!)"

echo ""
echo "4. Summary of generated files:"
echo "   testdata/"
ls -1 *.pb.go 2>/dev/null | sed 's/^/     /'
echo "   testdata/crossfile/"
ls -1 crossfile/*.pb.go 2>/dev/null | sed 's/^/     /' | sed 's/crossfile\///'

echo ""
echo "5. Running tests..."
(cd .. && go test -v ./...)

echo ""
echo "=========================================="
echo "✓ All done!"
echo "=========================================="
