// Redact returns a redacted JSON string representation of {{.Name}}.
// Sensitive fields are masked to prevent accidental logging of sensitive data.
func (x *{{.Name}}) Redact() string {
	if x == nil {
		return "{}"
	}
	clone := proto.Clone(x).(*{{.Name}})
{{- range .Fields}}
{{- if .Redact}}
	clone.{{.GoName}} = "{{.Mask}}"
{{- end}}
{{- end}}
	b, _ := protojson.Marshal(clone)
	return string(b)
}

