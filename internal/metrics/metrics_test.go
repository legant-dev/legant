package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestCounterExposition(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("legant_test_total", "A test counter.", "method", "code")
	c.Inc("GET", "200")
	c.Inc("GET", "200")
	c.Inc("POST", "500")

	out := render(r)
	want := []string{
		"# HELP legant_test_total A test counter.",
		"# TYPE legant_test_total counter",
		`legant_test_total{method="GET",code="200"} 2`,
		`legant_test_total{method="POST",code="500"} 1`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("exposition missing %q\n--- got ---\n%s", w, out)
		}
	}
}

func TestGaugeUpDown(t *testing.T) {
	r := NewRegistry()
	g := r.NewGauge("legant_inflight", "In flight.")
	g.Inc()
	g.Inc()
	g.Dec()
	out := render(r)
	if !strings.Contains(out, "legant_inflight 1") {
		t.Errorf("gauge value wrong\n%s", out)
	}
	if !strings.Contains(out, "# TYPE legant_inflight gauge") {
		t.Errorf("gauge type line missing\n%s", out)
	}
}

func TestHistogramCumulativeBuckets(t *testing.T) {
	r := NewRegistry()
	h := r.NewHistogram("legant_dur_seconds", "Durations.", []float64{0.1, 0.5, 1}, "route")
	// Observations: 0.05 -> le 0.1; 0.2 -> le 0.5; 2 -> +Inf only.
	h.Observe(0.05, "/a")
	h.Observe(0.2, "/a")
	h.Observe(2.0, "/a")

	out := render(r)
	want := []string{
		`legant_dur_seconds_bucket{route="/a",le="0.1"} 1`,
		`legant_dur_seconds_bucket{route="/a",le="0.5"} 2`,
		`legant_dur_seconds_bucket{route="/a",le="1"} 2`,
		`legant_dur_seconds_bucket{route="/a",le="+Inf"} 3`,
		`legant_dur_seconds_count{route="/a"} 3`,
		`legant_dur_seconds_sum{route="/a"} 2.25`,
		"# TYPE legant_dur_seconds histogram",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("histogram exposition missing %q\n--- got ---\n%s", w, out)
		}
	}
}

func TestLabelValueEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("legant_esc_total", "Escaping.", "path")
	c.Inc(`a"b\c`)
	out := render(r)
	if !strings.Contains(out, `legant_esc_total{path="a\"b\\c"} 1`) {
		t.Errorf("label not escaped\n%s", out)
	}
}

func TestGoCollector(t *testing.T) {
	r := NewRegistry()
	r.AddGoCollector()
	out := render(r)
	for _, name := range []string{"go_goroutines", "go_memstats_alloc_bytes", "go_gc_cycles_total"} {
		if !strings.Contains(out, name) {
			t.Errorf("go collector missing %q", name)
		}
	}
}

func TestMiddlewareRecordsRequest(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/agents/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/agents/abc123", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	out := render(Default)
	// The route LABEL must be the chi pattern, never the raw path — otherwise a
	// per-id path explodes label cardinality.
	if !strings.Contains(out, `route="/agents/{id}"`) {
		t.Errorf("expected route pattern label, got:\n%s", out)
	}
	if strings.Contains(out, "abc123") {
		t.Errorf("raw path id leaked into a metric label:\n%s", out)
	}
	if !strings.Contains(out, `legant_http_requests_total{method="GET",route="/agents/{id}",code="418"} `) {
		t.Errorf("request not counted with status:\n%s", out)
	}
	if !strings.Contains(out, "legant_http_request_duration_seconds_bucket") {
		t.Errorf("duration histogram not recorded:\n%s", out)
	}
}

func render(r *Registry) string {
	var b bytes.Buffer
	r.Render(&b)
	return b.String()
}
