package main

import (
	"flag"
	"fmt"

	"github.com/crypto-zero/go-kit/logging/protoc-gen-go-redact/internal/redact"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/types/pluginpb"
)

var showVersion = flag.Bool("version", false, "print the version and exit")

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("protoc-gen-go-redact %v\n", redact.Release)
		return
	}
	protogen.Options{
		ParamFunc: flag.CommandLine.Set,
	}.Run(func(gen *protogen.Plugin) error {
		gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)

		// Phase 1: Global analysis - collect all messages needing redaction across ALL files
		// This enables cross-file propagation of redact requirements
		needsRedact := redact.CollectGlobalRedactRequirements(gen.Files)

		// Phase 2: Generate code for each file using the global analysis result
		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}
			// GenerateFileWithGlobal uses pre-computed global needsRedact map
			redact.GenerateFileWithGlobal(gen, f, needsRedact)
		}
		return nil
	})
}
