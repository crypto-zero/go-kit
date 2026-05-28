package otel

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/crypto-zero/go-kit/kubernetes"
)

const traceShutdownTimeout = 5 * time.Second

// TraceProvider is an open telemetry trace service.
//
// Deprecated: This broad compatibility type is an alias-shaped service token.
// Consumers should depend on the behavior they need instead of this type.
type TraceProvider any

// TraceProviderConfig configures an OpenTelemetry trace provider.
type TraceProviderConfig struct {
	Context        context.Context
	Name           string
	Version        string
	Namespace      string
	Endpoint       string
	Insecure       bool
	SampleFraction float64
}

// FromEnv loads trace provider config from environment variables.
func (c *TraceProviderConfig) FromEnv() {
	value := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	// The env var may contain a scheme, which we need to remove.
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if value != "" {
		c.Endpoint = value
	}
}

// TraceProviderImpl is an OpenTelemetry trace service.
type TraceProviderImpl struct{}

// NewTraceProvider creates an OpenTelemetry trace provider.
//
// It returns TraceProvider for backward compatibility with earlier releases.
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
	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}
	exporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(exportGrpcOptions...))
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
		for attr := range strings.SplitSeq(resourceInEnv, ",") {
			parts := strings.Split(attr, "=")
			if len(parts) == 2 {
				attrs = append(attrs, attribute.String(parts[0], parts[1]))
			}
		}
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(c.SampleFraction)),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewSchemaless(attrs...)),
	)
	otel.SetTracerProvider(provider)
	return &TraceProviderImpl{}, func() {
		ctx, cancel := context.WithTimeout(context.Background(), traceShutdownTimeout)
		defer cancel()
		_ = provider.Shutdown(ctx)
	}, nil
}
