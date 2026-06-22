// Package metrics is a small, dependency-free Prometheus metrics registry. It
// implements just enough of the text exposition format (counters, histograms,
// gauges) to instrument Legant without pulling in the full client library — in
// keeping with the project's lean-dependency posture. The default registry is
// pre-loaded with HTTP request metrics, a Go-runtime collector, and the
// product-level counters (token exchanges, revocations, gateway calls).
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// DefaultBuckets are the request-duration histogram buckets, in seconds.
var DefaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// ---- Registry --------------------------------------------------------------

// Registry holds a set of metric families and renders them in the Prometheus
// text exposition format. It is safe for concurrent use.
type Registry struct {
	mu         sync.Mutex
	counters   []*CounterVec
	gauges     []*GaugeVec
	histograms []*HistogramVec
	collectors []func(w io.Writer)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// NewCounter registers and returns a labeled counter family.
func (r *Registry) NewCounter(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{name: name, help: help, labels: labels, series: map[string]*counterCell{}}
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// NewGauge registers and returns a labeled gauge family (a value that can go up
// and down, e.g. in-flight requests).
func (r *Registry) NewGauge(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{name: name, help: help, labels: labels, series: map[string]*gaugeCell{}}
	r.mu.Lock()
	r.gauges = append(r.gauges, g)
	r.mu.Unlock()
	return g
}

// NewHistogram registers and returns a labeled histogram family.
func (r *Registry) NewHistogram(name, help string, buckets []float64, labels ...string) *HistogramVec {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	h := &HistogramVec{name: name, help: help, labels: labels, buckets: b, series: map[string]*histogramCell{}}
	r.mu.Lock()
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
	return h
}

// AddCollector registers a callback that writes additional exposition lines at
// scrape time (used for runtime gauges sampled on demand).
func (r *Registry) AddCollector(fn func(w io.Writer)) {
	r.mu.Lock()
	r.collectors = append(r.collectors, fn)
	r.mu.Unlock()
}

// Render renders all registered metrics in the text exposition format.
func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	counters := append([]*CounterVec(nil), r.counters...)
	gauges := append([]*GaugeVec(nil), r.gauges...)
	histograms := append([]*HistogramVec(nil), r.histograms...)
	collectors := make([]func(io.Writer), len(r.collectors))
	copy(collectors, r.collectors)
	r.mu.Unlock()

	for _, c := range counters {
		c.write(w)
	}
	for _, g := range gauges {
		g.write(w)
	}
	for _, h := range histograms {
		h.write(w)
	}
	for _, fn := range collectors {
		fn(w)
	}
}

// Handler returns an http.Handler that serves the registry's metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Render(w)
	})
}

// ---- CounterVec ------------------------------------------------------------

// CounterVec is a family of monotonically increasing counters partitioned by a
// fixed set of label names.
type CounterVec struct {
	name, help string
	labels     []string
	mu         sync.RWMutex
	series     map[string]*counterCell
}

type counterCell struct {
	values []string
	v      atomic.Uint64
}

// Inc increments the counter for the given label values by one.
func (c *CounterVec) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add adds n to the counter for the given label values.
func (c *CounterVec) Add(n uint64, labelValues ...string) {
	c.cell(labelValues).v.Add(n)
}

func (c *CounterVec) cell(values []string) *counterCell {
	key := joinKey(values)
	c.mu.RLock()
	cell, ok := c.series[key]
	c.mu.RUnlock()
	if ok {
		return cell
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cell, ok = c.series[key]; ok {
		return cell
	}
	cell = &counterCell{values: append([]string(nil), values...)}
	c.series[key] = cell
	return cell
}

func (c *CounterVec) write(w io.Writer) {
	writeHeader(w, c.name, c.help, "counter")
	c.mu.RLock()
	cells := make([]*counterCell, 0, len(c.series))
	for _, cell := range c.series {
		cells = append(cells, cell)
	}
	c.mu.RUnlock()
	sort.Slice(cells, func(i, j int) bool { return joinKey(cells[i].values) < joinKey(cells[j].values) })
	for _, cell := range cells {
		fmt.Fprintf(w, "%s%s %d\n", c.name, renderLabels(c.labels, cell.values), cell.v.Load())
	}
}

// ---- GaugeVec --------------------------------------------------------------

// GaugeVec is a family of gauges (values that go up and down) partitioned by a
// fixed set of label names. Values are integers, sufficient for counts such as
// in-flight requests.
type GaugeVec struct {
	name, help string
	labels     []string
	mu         sync.RWMutex
	series     map[string]*gaugeCell
}

type gaugeCell struct {
	values []string
	v      atomic.Int64
}

// Inc increments the gauge for the given label values by one.
func (g *GaugeVec) Inc(labelValues ...string) { g.cell(labelValues).v.Add(1) }

// Dec decrements the gauge for the given label values by one.
func (g *GaugeVec) Dec(labelValues ...string) { g.cell(labelValues).v.Add(-1) }

func (g *GaugeVec) cell(values []string) *gaugeCell {
	key := joinKey(values)
	g.mu.RLock()
	cell, ok := g.series[key]
	g.mu.RUnlock()
	if ok {
		return cell
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if cell, ok = g.series[key]; ok {
		return cell
	}
	cell = &gaugeCell{values: append([]string(nil), values...)}
	g.series[key] = cell
	return cell
}

func (g *GaugeVec) write(w io.Writer) {
	writeHeader(w, g.name, g.help, "gauge")
	g.mu.RLock()
	cells := make([]*gaugeCell, 0, len(g.series))
	for _, cell := range g.series {
		cells = append(cells, cell)
	}
	g.mu.RUnlock()
	sort.Slice(cells, func(i, j int) bool { return joinKey(cells[i].values) < joinKey(cells[j].values) })
	for _, cell := range cells {
		fmt.Fprintf(w, "%s%s %d\n", g.name, renderLabels(g.labels, cell.values), cell.v.Load())
	}
}

// ---- HistogramVec ----------------------------------------------------------

// HistogramVec is a family of histograms partitioned by a fixed set of labels.
type HistogramVec struct {
	name, help string
	labels     []string
	buckets    []float64
	mu         sync.RWMutex
	series     map[string]*histogramCell
}

type histogramCell struct {
	values  []string
	counts  []atomic.Uint64 // per-bucket (non-cumulative); last entry is +Inf
	sumBits atomic.Uint64   // float64 bits of the running sum
	count   atomic.Uint64
}

// Observe records a single observation for the given label values.
func (h *HistogramVec) Observe(v float64, labelValues ...string) {
	cell := h.cell(labelValues)
	idx := sort.SearchFloat64s(h.buckets, v)
	cell.counts[idx].Add(1)
	cell.count.Add(1)
	for {
		old := cell.sumBits.Load()
		nv := math.Float64bits(math.Float64frombits(old) + v)
		if cell.sumBits.CompareAndSwap(old, nv) {
			break
		}
	}
}

func (h *HistogramVec) cell(values []string) *histogramCell {
	key := joinKey(values)
	h.mu.RLock()
	cell, ok := h.series[key]
	h.mu.RUnlock()
	if ok {
		return cell
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if cell, ok = h.series[key]; ok {
		return cell
	}
	cell = &histogramCell{
		values: append([]string(nil), values...),
		counts: make([]atomic.Uint64, len(h.buckets)+1), // +1 for the +Inf bucket
	}
	h.series[key] = cell
	return cell
}

func (h *HistogramVec) write(w io.Writer) {
	writeHeader(w, h.name, h.help, "histogram")
	h.mu.RLock()
	cells := make([]*histogramCell, 0, len(h.series))
	for _, cell := range h.series {
		cells = append(cells, cell)
	}
	h.mu.RUnlock()
	sort.Slice(cells, func(i, j int) bool { return joinKey(cells[i].values) < joinKey(cells[j].values) })

	for _, cell := range cells {
		var cumulative uint64
		for i, b := range h.buckets {
			cumulative += cell.counts[i].Load()
			labels := appendLabel(h.labels, cell.values, "le", formatFloat(b))
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, labels, cumulative)
		}
		cumulative += cell.counts[len(h.buckets)].Load()
		infLabels := appendLabel(h.labels, cell.values, "le", "+Inf")
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, infLabels, cumulative)
		base := renderLabels(h.labels, cell.values)
		fmt.Fprintf(w, "%s_sum%s %s\n", h.name, base, formatFloat(math.Float64frombits(cell.sumBits.Load())))
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, base, cell.count.Load())
	}
}

// ---- runtime collector -----------------------------------------------------

// AddGoCollector registers gauges sampled from the Go runtime at scrape time.
func (r *Registry) AddGoCollector() {
	r.AddCollector(func(w io.Writer) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		writeHeader(w, "go_goroutines", "Number of goroutines that currently exist.", "gauge")
		fmt.Fprintf(w, "go_goroutines %d\n", runtime.NumGoroutine())
		writeHeader(w, "go_memstats_alloc_bytes", "Number of bytes allocated and still in use.", "gauge")
		fmt.Fprintf(w, "go_memstats_alloc_bytes %d\n", m.Alloc)
		writeHeader(w, "go_memstats_heap_inuse_bytes", "Number of heap bytes that are in use.", "gauge")
		fmt.Fprintf(w, "go_memstats_heap_inuse_bytes %d\n", m.HeapInuse)
		writeHeader(w, "go_gc_cycles_total", "Number of completed GC cycles.", "counter")
		fmt.Fprintf(w, "go_gc_cycles_total %d\n", m.NumGC)
		writeHeader(w, "go_threads", "Number of OS threads created.", "gauge")
		fmt.Fprintf(w, "go_threads %d\n", pprofThreadCount())
	})
}

// SetBuildInfo registers a constant build_info gauge labeled with the version.
func (r *Registry) SetBuildInfo(version, goVersion string) {
	r.AddCollector(func(w io.Writer) {
		writeHeader(w, "legant_build_info", "Build metadata; the value is always 1.", "gauge")
		fmt.Fprintf(w, "legant_build_info%s 1\n",
			renderLabels([]string{"version", "go_version"}, []string{version, goVersion}))
	})
}

func pprofThreadCount() int {
	n, _ := runtime.ThreadCreateProfile(nil)
	return n
}

// ---- exposition helpers ----------------------------------------------------

func writeHeader(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, escapeHelp(help))
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func renderLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := ""
		if i < len(values) {
			v = values[i]
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(v))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// appendLabel renders the base labels plus one extra (name=value), used for the
// histogram "le" bucket label.
func appendLabel(names, values []string, extraName, extraValue string) string {
	n := append(append([]string(nil), names...), extraName)
	v := append(append([]string(nil), values...), extraValue)
	return renderLabels(n, v)
}

// joinKey builds a collision-free map key from label values by length-prefixing
// each value, so tuples like {"a","b"} and {"a\x1fb"} can never alias.
func joinKey(values []string) string {
	var b strings.Builder
	for _, v := range values {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`).Replace(s)
}

func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(s)
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
