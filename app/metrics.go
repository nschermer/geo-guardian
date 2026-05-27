package main

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// boundedSyncMap is a sync.Map that stops accepting new keys once max is reached.
type boundedSyncMap struct {
	m   sync.Map
	n   atomic.Int64
	max int64
}

func (b *boundedSyncMap) increment(key string) {
	// Fast path: key already exists.
	if v, ok := b.m.Load(key); ok {
		v.(*atomic.Int64).Add(1)
		return
	}
	// Slow path: new key — enforce cap before storing.
	if b.n.Load() >= b.max {
		return
	}
	newVal := &atomic.Int64{}
	newVal.Add(1)
	if _, loaded := b.m.LoadOrStore(key, newVal); !loaded {
		b.n.Add(1)
	}
}

func (b *boundedSyncMap) rangeEntries(fn func(key string, val int64) bool) {
	b.m.Range(func(k, v any) bool {
		return fn(k.(string), v.(*atomic.Int64).Load())
	})
}

// Metrics tracks request statistics
type Metrics struct {
	internalAccepted  atomic.Int64
	cacheHits         atomic.Int64
	cacheMisses       atomic.Int64
	blockedPerCountry boundedSyncMap // capped at 500 (≈250 real country codes)
	allowedPerCountry boundedSyncMap
	blockedPerHost    boundedSyncMap // capped at 10 000
	allowedPerHost    boundedSyncMap
	mu                sync.RWMutex // only guards geoipNodeCount and geoipBuildEpoch
	geoipNodeCount    uint
	geoipBuildEpoch   time.Time
}

func newMetrics() *Metrics {
	m := &Metrics{}
	m.blockedPerCountry.max = 500
	m.allowedPerCountry.max = 500
	m.blockedPerHost.max = 10_000
	m.allowedPerHost.max = 10_000
	return m
}

func (m *Metrics) RecordInternalRequest() {
	m.internalAccepted.Add(1)
}

func (m *Metrics) RecordAllowedRequest(country, host string) {
	if country != "" {
		m.allowedPerCountry.increment(country)
	}
	if host != "" {
		m.allowedPerHost.increment(host)
	}
}

func (m *Metrics) RecordBlockedRequest(country, host string) {
	if country != "" {
		m.blockedPerCountry.increment(country)
	}
	if host != "" {
		m.blockedPerHost.increment(host)
	}
}

func (m *Metrics) RecordAllowedHost(host string) {
	if host != "" {
		m.allowedPerHost.increment(host)
	}
}

func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Add(1)
}

func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Add(1)
}

func (m *Metrics) SetGeoIPInfo(nodeCount uint, buildEpoch time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.geoipNodeCount = nodeCount
	m.geoipBuildEpoch = buildEpoch
}

func (m *Metrics) GetStats() (internal int64, cacheHits int64, cacheMisses int64, geoipNodeCount uint, geoipBuildEpoch time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.internalAccepted.Load(), m.cacheHits.Load(), m.cacheMisses.Load(), m.geoipNodeCount, m.geoipBuildEpoch
}

func writeSyncMapMetrics(buf *bytes.Buffer, sm *boundedSyncMap, help, metricType, metricName, labelKey string) {
	first := true
	sm.rangeEntries(func(k string, val int64) bool {
		if first {
			fmt.Fprintf(buf, "# HELP %s %s\n# TYPE %s %s\n", metricName, help, metricName, metricType)
			first = false
		}
		fmt.Fprintf(buf, "%s{%s=\"%s\"} %d\n", metricName, labelKey, k, val)
		return true
	})
	if !first {
		buf.WriteByte('\n')
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	internal, cacheHits, cacheMisses, geoipNodeCount, geoipBuildEpoch := metrics.GetStats()

	var buf bytes.Buffer

	// Write Prometheus metrics in text format
	fmt.Fprintf(&buf, "# HELP accepted_internal_total Counter of internal network requests accepted\n")
	fmt.Fprintf(&buf, "# TYPE accepted_internal_total counter\n")
	fmt.Fprintf(&buf, "accepted_internal_total %d\n\n", internal)

	fmt.Fprintf(&buf, "# HELP cache_hits_total Counter of cache hits\n")
	fmt.Fprintf(&buf, "# TYPE cache_hits_total counter\n")
	fmt.Fprintf(&buf, "cache_hits_total %d\n\n", cacheHits)

	fmt.Fprintf(&buf, "# HELP cache_misses_total Counter of cache misses\n")
	fmt.Fprintf(&buf, "# TYPE cache_misses_total counter\n")
	fmt.Fprintf(&buf, "cache_misses_total %d\n\n", cacheMisses)

	fmt.Fprintf(&buf, "# HELP geoip_node_count Total number of nodes in GeoIP database\n")
	fmt.Fprintf(&buf, "# TYPE geoip_node_count gauge\n")
	fmt.Fprintf(&buf, "geoip_node_count %d\n\n", geoipNodeCount)

	fmt.Fprintf(&buf, "# HELP geoip_build_timestamp GeoIP database build timestamp in milliseconds\n")
	fmt.Fprintf(&buf, "# TYPE geoip_build_timestamp gauge\n")
	fmt.Fprintf(&buf, "geoip_build_timestamp{date=\"%s\"} %d\n\n", geoipBuildEpoch.Format(time.RFC3339), geoipBuildEpoch.UnixMilli())

	writeSyncMapMetrics(&buf, &metrics.allowedPerCountry, "Counter of requests accepted per country", "counter", "accepted_country_total", "country")
	writeSyncMapMetrics(&buf, &metrics.blockedPerCountry, "Counter of requests blocked per country", "counter", "blocked_country_total", "country")
	writeSyncMapMetrics(&buf, &metrics.allowedPerHost, "Counter of requests accepted per host", "counter", "accepted_host_total", "host")
	writeSyncMapMetrics(&buf, &metrics.blockedPerHost, "Counter of requests blocked per host", "counter", "blocked_host_total", "host")

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write(buf.Bytes())
}
