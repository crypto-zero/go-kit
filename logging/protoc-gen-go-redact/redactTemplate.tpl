// redact returns a map representation with sensitive fields masked.
// This is used internally for recursive redaction without JSON escaping issues.
func (x *{{.Name}}) redact() map[string]any {
	if x == nil {
		return nil
	}
	m := make(map[string]any)
{{- range .Fields}}
{{- if .Redact}}
	m["{{.JSONName}}"] = "{{.Mask}}"
{{- else if and .IsMessage .IsRepeated}}
	if len(x.{{.GoName}}) > 0 {
		items := make([]any, len(x.{{.GoName}}))
		for i, item := range x.{{.GoName}} {
			if item != nil {
				if r, ok := any(item).(interface{ redact() map[string]any }); ok {
					items[i] = r.redact()
				} else {
					items[i] = json.RawMessage(protojson.Format(item))
				}
			}
		}
		m["{{.JSONName}}"] = items
	}
{{- else if .IsRepeated}}
	if len(x.{{.GoName}}) > 0 {
		m["{{.JSONName}}"] = x.{{.GoName}}
	}
{{- else if .IsMessage}}
	if x.{{.GoName}} != nil {
		if r, ok := any(x.{{.GoName}}).(interface{ redact() map[string]any }); ok {
			m["{{.JSONName}}"] = r.redact()
		} else {
			m["{{.JSONName}}"] = json.RawMessage(protojson.Format(x.{{.GoName}}))
		}
	}
{{- else}}
	m["{{.JSONName}}"] = x.{{.GoName}}
{{- end}}
{{- end}}
	return m
}

// Redact returns a redacted JSON string representation of {{.Name}}.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
// This method implements the Redacter interface for Kratos logging middleware.
func (x *{{.Name}}) Redact() string {
	if x == nil {
		return "{}"
	}
	b, _ := json.Marshal(x.redact())
	return string(b)
}

