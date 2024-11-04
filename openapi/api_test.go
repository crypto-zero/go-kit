package v1

import (
	"embed"
	"encoding/json"
	"testing"
)

//go:embed cms.openapi.yaml
var OpenAPIYAML embed.FS

func TestGenerateOpenAPI(t *testing.T) {
	apis, err := GenerateOpenAPI(&OpenAPIYAML)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(apis)
	t.Log(string(data))
}

func TestGenerateGRPCFullMethodNamesByTag(t *testing.T) {
	methods, err := GenerateGRPCFullMethodNamesByTag(&OpenAPIYAML, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(methods)
}
