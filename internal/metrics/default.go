package metrics

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// Default is the process-wide registry. It is pre-loaded with HTTP request
// metrics, a Go-runtime collector, and the product-level counters below.
var Default = NewRegistry()

// Product-level metrics. These are incremented at the relevant choke points
// (token exchange, revocation, gateway tool calls) to give an at-a-glance view
// of delegation activity that raw HTTP counts cannot.
var (
	HTTPRequestsTotal = Default.NewCounter(
		"legant_http_requests_total",
		"Total HTTP requests handled, by method, route pattern, and status code.",
		"method", "route", "code")

	HTTPRequestDuration = Default.NewHistogram(
		"legant_http_request_duration_seconds",
		"HTTP request latency in seconds, by method and route pattern.",
		DefaultBuckets, "method", "route")

	HTTPRequestsInFlight = Default.NewGauge(
		"legant_http_requests_in_flight",
		"Requests currently being served.")

	// TokenExchangesTotal counts RFC 8693 token-exchange attempts by outcome.
	TokenExchangesTotal = Default.NewCounter(
		"legant_token_exchanges_total",
		"RFC 8693 token-exchange attempts, by result (success|error).",
		"result")

	// DelegationsTotal counts delegations created (the top of the funnel): a user
	// consenting to delegate to an agent, or an agent re-delegating to a sub-agent.
	DelegationsTotal = Default.NewCounter(
		"legant_delegations_total",
		"Delegations created, by kind (consent|redelegate).",
		"kind")

	// TokensMintedTotal counts composite delegation tokens actually signed.
	TokensMintedTotal = Default.NewCounter(
		"legant_tokens_minted_total",
		"Composite delegation tokens minted, by source (exchange|gateway).",
		"source")

	// RevocationsTotal counts revocation events.
	RevocationsTotal = Default.NewCounter(
		"legant_revocations_total",
		"Revocation events, by kind (token|delegation).",
		"kind")

	// RevocationCheckErrorsTotal counts revocation-store lookup failures. These
	// fail closed (the request is denied), so without a metric they are invisible —
	// a spike means the store is unhealthy and tokens are being rejected.
	RevocationCheckErrorsTotal = Default.NewCounter(
		"legant_revocation_check_errors_total",
		"Revocation-store lookup failures, by component (gateway|introspection).",
		"component")

	// GatewayCallsTotal counts MCP gateway tool calls by upstream and decision.
	GatewayCallsTotal = Default.NewCounter(
		"legant_gateway_calls_total",
		"MCP gateway tool calls, by upstream and decision (allow|deny|unauthorized|error).",
		"upstream", "decision")
)

func init() {
	Default.AddGoCollector()
}

// SetBuildInfo records the running version as a build_info gauge.
func SetBuildInfo(version string) {
	Default.SetBuildInfo(version, runtime.Version())
}

// Handler serves the default registry's metrics in the Prometheus text format.
func Handler() http.Handler { return Default.Handler() }

// Middleware records request count and latency for every HTTP request, labeled
// by method, the chi route pattern (bounded cardinality — never the raw path),
// and status code.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		HTTPRequestsInFlight.Inc()
		defer HTTPRequestsInFlight.Dec()
		next.ServeHTTP(sw, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "other"
		}
		method := normalizeMethod(r.Method)
		HTTPRequestsTotal.Inc(method, route, strconv.Itoa(sw.status))
		HTTPRequestDuration.Observe(time.Since(start).Seconds(), method, route)
	})
}

// knownMethods bounds the `method` label: an attacker can send arbitrary request
// methods, and labeling by the raw value would let them grow the metric series
// set without limit (memory-exhaustion DoS). Unknown methods collapse to "other".
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodConnect: true, http.MethodOptions: true, http.MethodTrace: true,
}

func normalizeMethod(m string) string {
	if knownMethods[m] {
		return m
	}
	return "other"
}

// statusWriter captures the response status code while delegating optional
// interfaces (Flusher) that streaming handlers rely on.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped ResponseWriter so http.NewResponseController can
// reach the base connection (e.g. to clear the write deadline for SSE).
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
