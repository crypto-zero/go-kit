package main

import (
	"bytes"
	_ "embed"
	"strings"
	"text/template"
)

//go:embed redactTemplate.tpl
var redactTemplate string

type messageDesc struct {
	Name   string       // Message name (e.g., "User")
	Fields []*fieldDesc // Fields in the message
}

type fieldDesc struct {
	GoName     string // Go field name (e.g., "Email")
	JSONName   string // JSON field name (e.g., "email")
	Redact     bool   // Whether this field should be redacted
	Mask       string // Mask string (e.g., "*")
	IsMessage  bool   // Whether this field is a proto message type
	IsRepeated bool   // Whether this field is a repeated field
}

func (m *messageDesc) execute() string {
	buf := new(bytes.Buffer)
	tmpl, err := template.New("redact").Parse(strings.TrimSpace(redactTemplate))
	if err != nil {
		panic(err)
	}
	if err := tmpl.Execute(buf, m); err != nil {
		panic(err)
	}
	return strings.Trim(buf.String(), "\r\n")
}
