package services

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
)

// TestInitTracingNoEndpointIsNoop confirms that with OTEL_EXPORTER_OTLP_
// ENDPOINT unset the function still returns a usable shutdown closure
// AND installs the W3C propagators. The propagators matter even
// without an exporter: an inbound traceparent header should still
// propagate to outbound HTTP clients so a downstream service can
// continue the trace.
func TestInitTracingNoEndpointIsNoop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	shutdown, err := InitTracing(context.Background(), "test", "0.0.0")
	if err != nil {
		t.Fatalf("InitTracing returned err = %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown closure is nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown returned err = %v", err)
	}

	// Propagator must be installed so downstream code doing
	// otel.GetTextMapPropagator().Inject(...) emits a traceparent
	// header. The zero-value default returns "", so a non-empty
	// Fields() slice is the signal that we installed our composite.
	if fields := otel.GetTextMapPropagator().Fields(); len(fields) == 0 {
		t.Errorf("global propagator has no fields — composite not installed")
	}
}

// TestInitTracingInvalidEndpoint is a smoke test for the error path:
// pointing at an unresolvable host should still return without panic
// and without leaving a half-constructed TracerProvider behind. The
// OTLP HTTP exporter is lazy about dialing, so the error surfaces on
// the first export rather than from InitTracing itself — this test
// just verifies the constructor doesn't trip on a malformed-looking
// endpoint.
func TestInitTracingMalformedEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1") // unused port
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	shutdown, err := InitTracing(context.Background(), "test", "0.0.0")
	if err != nil {
		// The exporter is lazy about dialing; if the constructor
		// does error here we still want a clean state (shutdown nil
		// is OK). Don't fail — just stop, since the contract is
		// "no leak, no panic," not "no error."
		t.Logf("InitTracing returned err = %v (acceptable for invalid endpoint)", err)
		return
	}
	if shutdown == nil {
		t.Fatal("shutdown closure is nil but err is nil")
	}
	// Shutdown should not hang or panic on a misconfigured exporter.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = shutdown(ctx)
}
