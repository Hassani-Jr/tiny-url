package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRecoverCatchesPanic(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	handler := Recover(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))

	req := httptest.NewRequest(http.MethodGet, "/explode", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if !strings.Contains(w.Body.String(), "internal server error") {
		t.Errorf("body = %q, want body to mention internal error", w.Body.String())
	}
	if !strings.Contains(buf.String(), `"panic":"boom"`) {
		t.Errorf("slog output should include panic value; got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"stack":`) {
		t.Errorf("slog output should include a stack trace; got: %s", buf.String())
	}
}

func TestRecoverPassesThroughHealthyHandler(t *testing.T) {
	handler := Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hi"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418 (Recover should not interfere with normal responses)", w.Code)
	}
	if w.Body.String() != "hi" {
		t.Errorf("body = %q, want %q", w.Body.String(), "hi")
	}
}

func TestRecoverIncrementsCounter(t *testing.T) {
	before := readPanicsTotal(t)
	handler := Recover(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("counted")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	after := readPanicsTotal(t)
	if after != before+1 {
		t.Errorf("panics_total: before=%g after=%g, want +1", before, after)
	}
}

// readPanicsTotal reads the current value of the Prometheus counter via
// Collect(). The client_golang Counter type doesn't expose a getter, but
// Collect emits a prometheus.Metric whose .Write fills a dto.Metric we
// can inspect.
func readPanicsTotal(t *testing.T) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	panicsTotal.Collect(ch)
	close(ch)
	m := <-ch
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return pb.GetCounter().GetValue()
}
