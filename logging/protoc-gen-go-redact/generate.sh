#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "1. Building plugin..."
go build -o protoc-gen-go-redact .

echo "2. Generating redact code..."
protoc --proto_path=../../proto --proto_path=. --plugin=protoc-gen-go-redact=./protoc-gen-go-redact --go-redact_out=. --go-redact_opt=paths=source_relative testdata/example.proto

echo "3. Verifying generated file..."
ls -la testdata/example_redact.pb.go

echo "4. Running tests..."
go test -v ./...

echo "Done!"

