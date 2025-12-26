// redact returns a map representation with sensitive fields masked.
// This is used internally for recursive redaction without JSON escaping issues.
func (x *{{.Name}}) redact() map[string]any {
	if x == nil {
		return nil
	}
	m := make(map[string]any)
{{- range .Fields}}
{{- if .Redact}}
{{- if .IsRepeated}}
	m["{{.JSONName}}"] = []any{}
{{- else if .IsMap}}
	m["{{.JSONName}}"] = map[string]any{}
{{- else if .IsMessage}}
	m["{{.JSONName}}"] = nil
{{- else if .IsNumeric}}
	m["{{.JSONName}}"] = int64({{.IntMask}})
{{- else if .IsFloat}}
	m["{{.JSONName}}"] = float64({{.DoubleMask}})
{{- else if .IsBool}}
	m["{{.JSONName}}"] = {{.BoolMask}}
{{- else if .IsBytes}}
	m["{{.JSONName}}"] = {{.BytesMask | quote}}
{{- else if .IsEnum}}
	m["{{.JSONName}}"] = int32({{.EnumMask}})
{{- else}}
	m["{{.JSONName}}"] = {{.StringMask | quote}}
{{- end}}
{{- else if .IsMap}}
	if len(x.{{.GoName}}) > 0 {
		mapVal := make(map[string]any)
		for k, v := range x.{{.GoName}} {
			key := fmt.Sprintf("%v", k)
{{- if .MapValueIsMessage}}
			if v != nil {
				if r, ok := any(v).(interface{ redact() map[string]any }); ok {
					mapVal[key] = r.redact()
				} else {
					mapVal[key] = json.RawMessage(protojson.Format(v))
				}
			}
{{- else}}
			mapVal[key] = v
{{- end}}
		}
		m["{{.JSONName}}"] = mapVal
	}
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
{{- if .IsOneof}}
	if x.Get{{.GoName}}() != nil {
		if r, ok := any(x.Get{{.GoName}}()).(interface{ redact() map[string]any }); ok {
			m["{{.JSONName}}"] = r.redact()
		} else {
			m["{{.JSONName}}"] = json.RawMessage(protojson.Format(x.Get{{.GoName}}()))
		}
	}
{{- else}}
	if x.{{.GoName}} != nil {
		if r, ok := any(x.{{.GoName}}).(interface{ redact() map[string]any }); ok {
			m["{{.JSONName}}"] = r.redact()
		} else {
			m["{{.JSONName}}"] = json.RawMessage(protojson.Format(x.{{.GoName}}))
		}
	}
{{- end}}
{{- else if .IsOneof}}
	m["{{.JSONName}}"] = x.Get{{.GoName}}()
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

