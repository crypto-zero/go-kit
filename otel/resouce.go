package otel

import "go.opentelemetry.io/otel/attribute"

const (
	// SigNozSystemDBKey is the span attribute key for database calls.
	// https://signoz.io/docs/userguide/metrics/
	SigNozSystemDBKey = attribute.Key("db.system")
)

// SigNozSystemDB returns a database system attribute.
func SigNozSystemDB(system string) attribute.KeyValue {
	return SigNozSystemDBKey.String(system)
}

// SigNozSystemDBPostgres returns a database system attribute for PostgreSQL.
func SigNozSystemDBPostgres() attribute.KeyValue {
	return SigNozSystemDB("postgresql")
}

// SigNozSystemDBNats returns a database system attribute for NATS.
func SigNozSystemDBNats() attribute.KeyValue {
	return SigNozSystemDB("nats")
}
