package main

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks request statistics
type Metrics struct {
	internalAccepted  atomic.Int64
	cacheHits         atomic.Int64
	cacheMisses       atomic.Int64
	blockedPerCountry sync.Map // string -> *atomic.Int64
	allowedPerCountry sync.Map
	blockedPerHost    sync.Map
	allowedPerHost    sync.Map
	mu                sync.RWMutex // only guards geoipNodeCount and geoipBuildEpoch
	geoipNodeCount    uint
	geoipBuildEpoch   time.Time
}

func incrementSyncMap(m *sync.Map, key string) {
	v, _ := m.LoadOrStore(key, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

func (m *Metrics) RecordInternalRequest() {
	m.internalAccepted.Add(1)
}

func (m *Metrics) RecordAllowedRequest(country, host string) {
	if country != "" {
		incrementSyncMap(&m.allowedPerCountry, country)
	}
	if host != "" {
		incrementSyncMap(&m.allowedPerHost, host)
	}
}

func (m *Metrics) RecordBlockedRequest(country, host string) {
	if country != "" {
		incrementSyncMap(&m.blockedPerCountry, country)
	}
	if host != "" {
		incrementSyncMap(&m.blockedPerHost, host)
	}
}

func (m *Metrics) RecordAllowedHost(host string) {
	if host != "" {
		incrementSyncMap(&m.allowedPerHost, host)
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

func syncMapToMap(sm *sync.Map) map[string]int64 {
	out := make(map[string]int64)
	sm.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

func (m *Metrics) GetCountryStats() (blocked map[string]int64, allowed map[string]int64) {
	return syncMapToMap(&m.blockedPerCountry), syncMapToMap(&m.allowedPerCountry)
}

func (m *Metrics) GetHostStats() (blocked map[string]int64, allowed map[string]int64) {
	return syncMapToMap(&m.blockedPerHost), syncMapToMap(&m.allowedPerHost)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	internal, cacheHits, cacheMisses, geoipNodeCount, geoipBuildEpoch := metrics.GetStats()
	blockedPerCountry, allowedPerCountry := metrics.GetCountryStats()
	blockedPerHost, allowedPerHost := metrics.GetHostStats()

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

	if len(allowedPerCountry) > 0 {
		fmt.Fprintf(&buf, "# HELP accepted_country_total Counter of requests accepted per country\n")
		fmt.Fprintf(&buf, "# TYPE accepted_country_total counter\n")
		for country, count := range allowedPerCountry {
			fmt.Fprintf(&buf, "accepted_country_total{country=\"%s\"} %d\n", country, count)
		}
		buf.WriteByte('\n')
	}

	if len(blockedPerCountry) > 0 {
		fmt.Fprintf(&buf, "# HELP blocked_country_total Counter of requests blocked per country\n")
		fmt.Fprintf(&buf, "# TYPE blocked_country_total counter\n")
		for country, count := range blockedPerCountry {
			fmt.Fprintf(&buf, "blocked_country_total{country=\"%s\"} %d\n", country, count)
		}
		buf.WriteByte('\n')
	}

	if len(allowedPerHost) > 0 {
		fmt.Fprintf(&buf, "# HELP accepted_host_total Counter of requests accepted per host\n")
		fmt.Fprintf(&buf, "# TYPE accepted_host_total counter\n")
		for host, count := range allowedPerHost {
			fmt.Fprintf(&buf, "accepted_host_total{host=\"%s\"} %d\n", host, count)
		}
		buf.WriteByte('\n')
	}

	if len(blockedPerHost) > 0 {
		fmt.Fprintf(&buf, "# HELP blocked_host_total Counter of requests blocked per host\n")
		fmt.Fprintf(&buf, "# TYPE blocked_host_total counter\n")
		for host, count := range blockedPerHost {
			fmt.Fprintf(&buf, "blocked_host_total{host=\"%s\"} %d\n", host, count)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write(buf.Bytes())
}
