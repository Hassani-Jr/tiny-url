package services

import (
	"context"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// InitTracing wires up an OTLP/HTTP trace exporter when an endpoint is
// configured and registers a global W3C trace-context propagator either
// way. Returns a shutdown function the caller must defer at the end of
// process lifetime so in-flight batches are flushed.
//
// The exporter is configured purely from the standard OpenTelemetry
// environment variables (OTEL_EXPORTER_OTLP_ENDPOINT,
// OTEL_EXPORTER_OTLP_HEADERS, etc.) — operators who already know how
// to point an OTel-instrumented binary at their backend don't need to
// learn a custom config. The serviceName and version fall back to
// args when OTEL_SERVICE_NAME isn't set.
//
// When the endpoint variable is unset the function returns early with
// a no-op shutdown: the global TracerProvider stays the default
// no-op implementation, so otel.Tracer(...) calls anywhere in the
// codebase become free.
func InitTracing(ctx context.Context, serviceName, version string) (func(context.Context) error, error) {
	// Always install a propagator so inbound traceparent headers are
	// honored and outbound HTTP clients propagate trace context, even
	// when we don't have a local exporter — that lets a downstream
	// service still attribute child spans to the inbound parent.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" &&
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		slog.Info("tracing disabled (OTEL_EXPORTER_OTLP_ENDPOINT not set)")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx) // reads env for endpoint/headers
	if err != nil {
		return nil, err
	}

	// Resource: service.name + service.version so traces in the
	// backend group cleanly per deployment. The OTel SDK also folds in
	// telemetry.sdk.* attributes automatically; we just add the
	// service-identifying ones.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	slog.Info("tracing enabled",
		"service", serviceName,
		"endpoint", firstNonEmpty(
			os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
			os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		),
	)
	return tp.Shutdown, nil
}

// firstNonEmpty returns the first non-"" string. Used to pick which
// OTEL_* env var actually provided the endpoint for the log line.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
