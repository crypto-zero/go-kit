package otel

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/crypto-zero/go-kit/kubernetes"
)

// TraceProviderConfig is an open telemetry trace provider config.
type TraceProviderConfig struct {
	Context        context.Context
	Name           string
	Version        string
	Namespace      string
	Endpoint       string
	Insecure       bool
	SampleFraction float64
}

// FromEnv load config from env.
func (c *TraceProviderConfig) FromEnv() {
	value := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	// The env var may contain a scheme, which we need to remove.
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if value != "" {
		c.Endpoint = value
	}
}

// TraceProvider is an open telemetry trace service.
type TraceProvider interface{}

type TraceProviderImpl struct{}

// NewTraceProvider new an open telemetry trace provider.
func NewTraceProvider(c *TraceProviderConfig) (
	TraceProvider, func(), error,
) {
	if c.Name == "" || c.Version == "" || c.Endpoint == "" {
		return nil, nil, fmt.Errorf("otel trace provider config name, version, endpoint must not be empty")
	}

	var exportGrpcOptions []otlptracegrpc.Option
	if c.Insecure {
		exportGrpcOptions = append(exportGrpcOptions, otlptracegrpc.WithInsecure())
	}
	exportGrpcOptions = append(exportGrpcOptions, otlptracegrpc.WithEndpoint(c.Endpoint))
	exporter, err := otlptrace.New(c.Context, otlptracegrpc.NewClient(exportGrpcOptions...))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the collector exporter: %w", err)
	}

	instanceID, _ := os.Hostname()
	attrs := []attribute.KeyValue{
		semconv.ServiceNamespace(c.Namespace),
		semconv.ServiceName(c.Name),
		semconv.ServiceVersion(c.Version),
		semconv.ServiceInstanceID(instanceID),
		semconv.K8SNamespaceName(kubernetes.GetCurrentNamespace()),
	}
	if resourceInEnv := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); resourceInEnv != "" {
		for _, attr := range strings.Split(resourceInEnv, ",") {
			parts := strings.Split(attr, "=")
			if len(parts) == 2 {
				attrs = append(attrs, attribute.String(parts[0], parts[1]))
			}
		}
	}

	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.TraceIDRatioBased(c.SampleFraction)),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resource.NewSchemaless(attrs...)),
		),
	)
	return &TraceProviderImpl{}, func() {}, nil
}
