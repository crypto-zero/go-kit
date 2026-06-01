// Package config provides small helpers for loading protobuf-backed
// application configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// Options controls protobuf config decoding.
type Options struct {
	// DiscardUnknown controls whether unknown protobuf fields are ignored.
	DiscardUnknown bool
}

// LoadYAMLFile reads path and unmarshals its YAML content into out.
func LoadYAMLFile(path string, out proto.Message) error {
	return LoadYAMLFileOptions(path, out, Options{})
}

// LoadYAMLFileOptions reads path and unmarshals its YAML content into out.
func LoadYAMLFileOptions(path string, out proto.Message, opts Options) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return UnmarshalYAML(b, out, opts)
}

// UnmarshalYAML unmarshals YAML content into out through protojson.
func UnmarshalYAML(data []byte, out proto.Message, opts Options) error {
	var yamlValue any
	if err := yaml.Unmarshal(data, &yamlValue); err != nil {
		return err
	}
	normalized, err := normalizeYAML(yamlValue)
	if err != nil {
		return err
	}
	jsonValue, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	return protojson.UnmarshalOptions{
		DiscardUnknown: opts.DiscardUnknown,
	}.Unmarshal(jsonValue, out)
}

func normalizeYAML(v any) (any, error) {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			normalized, err := normalizeYAML(value)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			stringKey, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("yaml map key %v has type %T, want string", key, key)
			}
			normalized, err := normalizeYAML(value)
			if err != nil {
				return nil, err
			}
			out[stringKey] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(v))
		for _, value := range v {
			normalized, err := normalizeYAML(value)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
		return out, nil
	default:
		return v, nil
	}
}
