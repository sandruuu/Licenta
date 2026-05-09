// Package metrics provides a minimal stdlib-only Prometheus text-format
// exporter shared between PDP, gateway and the desktop apps. We
// deliberately avoid pulling in the prometheus/client_golang dependency
// — the surface area we need (a handful of counters + gauges) does not
// justify the transitive footprint, and the OpenMetrics text format is
// trivial to emit by hand.
//
// Usage:
//
//	reg := metrics.NewRegistry()
//	reqs := reg.NewCounter("ztna_pdp_authorize_requests_total", "Authorize requests received")
//	reqs.Inc()
//	mux.Handle("/metrics", reg)
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically non-decreasing integer metric.
type Counter struct {
	v atomic.Int64
}

// Inc adds 1.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds delta. Panics if delta < 0 — counters MUST NOT decrease.
func (c *Counter) Add(delta int64) {
	if delta < 0 {
		panic("metrics.Counter.Add: negative delta")
	}
	c.v.Add(delta)
}

// Value returns the current count.
func (c *Counter) Value() int64 { return c.v.Load() }

// Gauge is a value that can go up or down (e.g. active sessions).
type Gauge struct {
	v atomic.Int64
}

// Set replaces the value.
func (g *Gauge) Set(v int64) { g.v.Store(v) }

// Inc / Dec are convenience helpers.
func (g *Gauge) Inc()            { g.v.Add(1) }
func (g *Gauge) Dec()            { g.v.Add(-1) }
func (g *Gauge) Add(delta int64) { g.v.Add(delta) }

// Value returns the current value.
func (g *Gauge) Value() int64 { return g.v.Load() }

// metricEntry is the internal book-keeping for one registered metric.
type metricEntry struct {
	name      string
	help      string
	kind      string // "counter" or "gauge"
	counter   *Counter
	gauge     *Gauge
	gaugeFunc func() int64 // for live-computed gauges (e.g. process metrics)
}

// Registry holds a set of metrics and renders them as OpenMetrics text.
// Implements http.Handler so it can be plugged into any net/http mux.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]*metricEntry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{metrics: make(map[string]*metricEntry)}
}

// NewCounter registers and returns a new Counter. Panics on duplicate
// name — metric names should be deterministic at startup.
func (r *Registry) NewCounter(name, help string) *Counter {
	c := &Counter{}
	r.mustAdd(&metricEntry{name: name, help: help, kind: "counter", counter: c})
	return c
}

// NewGauge registers and returns a new Gauge.
func (r *Registry) NewGauge(name, help string) *Gauge {
	g := &Gauge{}
	r.mustAdd(&metricEntry{name: name, help: help, kind: "gauge", gauge: g})
	return g
}

// NewGaugeFunc registers a gauge whose value is computed on each scrape.
// Useful for read-only views of state owned elsewhere (e.g. queue depth).
func (r *Registry) NewGaugeFunc(name, help string, f func() int64) {
	r.mustAdd(&metricEntry{name: name, help: help, kind: "gauge", gaugeFunc: f})
}

func (r *Registry) mustAdd(e *metricEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.metrics[e.name]; exists {
		panic("metrics: duplicate metric registration: " + e.name)
	}
	r.metrics[e.name] = e
}

// ServeHTTP renders all metrics in OpenMetrics / Prometheus text format.
// Output is sorted by name for diff-stability.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	r.write(w)
}

func (r *Registry) write(w io.Writer) {
	r.mu.Lock()
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	r.mu.Unlock()
	sort.Strings(names)

	for _, n := range names {
		r.mu.Lock()
		e := r.metrics[n]
		r.mu.Unlock()
		if e == nil {
			continue
		}
		var v int64
		switch {
		case e.counter != nil:
			v = e.counter.Value()
		case e.gauge != nil:
			v = e.gauge.Value()
		case e.gaugeFunc != nil:
			v = e.gaugeFunc()
		}
		fmt.Fprintf(w, "# HELP %s %s\n", e.name, e.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", e.name, e.kind)
		fmt.Fprintf(w, "%s %d\n", e.name, v)
	}
}
