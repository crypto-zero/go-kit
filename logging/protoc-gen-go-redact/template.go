package main

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

//go:embed redactTemplate.tpl
var redactTemplate string

// Precompiled template (lazy initialization)
var (
	tmpl     *template.Template
	tmplOnce sync.Once
)

func getTemplate() *template.Template {
	tmplOnce.Do(func() {
		var err error
		tmpl, err = template.New("redact").Funcs(template.FuncMap{
			"quote": strconv.Quote,
		}).Parse(strings.TrimSpace(redactTemplate))
		if err != nil {
			panic(err)
		}
	})
	return tmpl
}

type messageDesc struct {
	Name   string       // Message name (e.g., "User")
	Fields []*fieldDesc // Fields in the message
}

type fieldDesc struct {
	GoName            string // Go field name (e.g., "Email")
	JSONName          string // JSON field name (e.g., "email")
	Redact            bool   // Whether this field should be redacted
	IsMessage         bool   // Whether this field is a proto message type
	IsRepeated        bool   // Whether this field is a repeated field
	IsInteger         bool   // Whether this field is an integer type (int32, int64, uint32, etc.)
	IsFloat           bool   // Whether this field is a float/double type
	IsBool            bool   // Whether this field is a bool type
	IsBytes           bool   // Whether this field is a bytes type
	IsEnum            bool   // Whether this field is an enum type
	IsMap             bool   // Whether this field is a map type
	IsOneof           bool   // Whether this field is part of a oneof
	MapValueIsMessage bool   // Whether the map value is a message type

	// Custom mask values for scalar types (other types use Go zero values)
	StringMask string  // Custom mask for string fields, default "*"
	IntMask    int64   // Custom mask for integer fields, default 0
	DoubleMask float64 // Custom mask for float/double fields, default 0
	BoolMask   bool    // Custom mask for bool fields, default false
	BytesMask  string  // Custom mask for bytes fields, default ""
	EnumMask   int32   // Custom mask for enum fields, default 0
}

func (m *messageDesc) execute() string {
	buf := new(bytes.Buffer)
	if err := getTemplate().Execute(buf, m); err != nil {
		panic(err)
	}
	return strings.Trim(buf.String(), "\r\n")
}
