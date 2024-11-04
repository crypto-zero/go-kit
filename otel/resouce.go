package otel

import "go.opentelemetry.io/otel/attribute"

const (
	// SigNozSystemDBKey span type database call
	// https://signoz.io/docs/userguide/metrics/
	SigNozSystemDBKey = attribute.Key("db.system")
)

// SigNozSystemDB return db system attribute
func SigNozSystemDB(system string) attribute.KeyValue {
	return SigNozSystemDBKey.String(system)
}

// SigNozSystemDBPostgres return db system attribute for postgres
func SigNozSystemDBPostgres() attribute.KeyValue {
	return SigNozSystemDB("postgresql")
}

// SigNozSystemDBNats return db system attribute for nats
func SigNozSystemDBNats() attribute.KeyValue {
	return SigNozSystemDB("nats")
}
