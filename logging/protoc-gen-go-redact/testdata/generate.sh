#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "1. Building plugin..."
(cd .. && go build -o protoc-gen-go-redact .)
if [ ! -f "../protoc-gen-go-redact" ]; then
    echo "ERROR: Plugin build failed!"
    exit 1
fi

echo "2. Generating base Go code (example.pb.go)..."
protoc --proto_path=../../../proto --proto_path=. --go_out=. --go_opt=paths=source_relative example.proto

echo "   Verifying example.pb.go..."
if [ ! -f "example.pb.go" ]; then
    echo "ERROR: example.pb.go not found!"
    echo "Files in testdata/:"
    ls -la .
    exit 1
fi
echo "   ✓ example.pb.go generated successfully"

echo "3. Generating redact code (example_redact.pb.go)..."
protoc --proto_path=../../../proto --proto_path=. --plugin=protoc-gen-go-redact=../protoc-gen-go-redact --go-redact_out=. --go-redact_opt=paths=source_relative example.proto 2>&1 | tee protoc_output.log

echo "   Verifying example_redact.pb.go..."
if [ ! -f "example_redact.pb.go" ]; then
    echo "ERROR: example_redact.pb.go not found!"
    echo "Files in testdata/:"
    ls -la .
    echo ""
    echo "Protoc output saved to protoc_output.log, check it for errors:"
    cat protoc_output.log
    exit 1
fi
echo "   ✓ example_redact.pb.go generated successfully"

echo "4. Summary of generated files:"
ls -lh example*.pb.go

echo "5. Running tests..."
(cd .. && go test -v ./...)

echo "Done!"

