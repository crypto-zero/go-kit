package v1

import (
	"embed"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// GenerateGRPCFullMethodNamesByTag generates full method names by tag
func GenerateGRPCFullMethodNamesByTag(fs *embed.FS, tag string) (out []string, err error) {
	apis, err := GenerateOpenAPI(fs)
	if err != nil {
		return nil, err
	}
	for _, api := range apis {
		for _, path := range api.Paths {
			if !slices.Contains(path.Tags, tag) {
				continue
			}
			p := fmt.Sprintf("/%s.%s/%s", api.Version, path.ServiceName, path.MethodName)
			out = append(out, p)
		}
	}
	return
}

// OpenAPI represents a openapi file
type OpenAPI struct {
	Version string
	Paths   []OpenAPIPath
}

// OpenAPIPath represents a path in openapi file
type OpenAPIPath struct {
	OperationID string
	Path        string
	Method      string
	Tags        []string
	// ServiceName split from OperationID
	ServiceName string
	// MethodName split from OperationID
	MethodName string
}

// GenerateOpenAPI generates openapi from embed.FS
func GenerateOpenAPI(fs *embed.FS) (out []*OpenAPI, err error) {
	files, err := fs.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".openapi.yaml") {
			continue
		}
		f, err := fs.Open(file.Name())
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		var api OpenAPI
		if err = ResolveAPIFile(&api, data); err != nil {
			return nil, err
		}
		out = append(out, &api)
	}
	return
}

// ResolveAPIFile resolves api file
func ResolveAPIFile(api *OpenAPI, file []byte) error {
	m := make(map[string]interface{})
	if err := yaml.Unmarshal(file, &m); err != nil {
		return err
	}
	infoNode, ok := m["info"]
	if !ok {
		return nil
	}
	info, ok := infoNode.(map[string]interface{})
	if !ok {
		return nil
	}
	versionNode, ok := info["version"]
	if !ok {
		return nil
	}
	version, ok := versionNode.(string)
	if !ok {
		return nil
	}
	api.Version = version
	paths, ok := m["paths"]
	if !ok {
		return nil
	}
	pathMap, ok := paths.(map[string]interface{})
	if !ok {
		return nil
	}
	for path, pathNode := range pathMap {
		pathMap, ok := pathNode.(map[string]interface{})
		if !ok {
			continue
		}
		for method, methodNode := range pathMap {
			methodMap, ok := methodNode.(map[string]interface{})
			if !ok {
				continue
			}
			operationIDNode, ok := methodMap["operationId"]
			if !ok {
				continue
			}
			operationID, ok := operationIDNode.(string)
			if !ok {
				continue
			}
			tagsNode, ok := methodMap["tags"]
			if !ok {
				continue
			}
			tags, ok := tagsNode.([]interface{})
			if !ok {
				continue
			}
			var tagStrs []string
			for _, tagNode := range tags {
				tag, ok := tagNode.(string)
				if !ok {
					continue
				}
				tagStrs = append(tagStrs, tag)
			}
			serviceName, methodName := "", ""
			if first := strings.Index(operationID, "_"); first > 0 {
				serviceName = operationID[:first]
				methodName = operationID[first+1:]
			}
			apiPath := OpenAPIPath{
				OperationID: operationID,
				Path:        path,
				Method:      strings.ToUpper(method),
				Tags:        tagStrs,
				ServiceName: serviceName,
				MethodName:  methodName,
			}
			api.Paths = append(api.Paths, apiPath)
		}
	}
	return nil
}
