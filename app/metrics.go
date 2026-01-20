package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics tracks request statistics
type Metrics struct {
	mu                sync.RWMutex
	internalAccepted  atomic.Int64
	cacheHits         atomic.Int64
	cacheMisses       atomic.Int64
	blockedPerCountry map[string]int64
	allowedPerCountry map[string]int64
	blockedPerHost    map[string]int64
	allowedPerHost    map[string]int64
	geoipNodeCount    uint
	geoipBuildEpoch   time.Time
}

func (m *Metrics) RecordInternalRequest() {
	m.internalAccepted.Add(1)
}

func (m *Metrics) RecordAllowedRequest(country, host string) {
	if country != "" || host != "" {
		m.mu.Lock()
		defer m.mu.Unlock()
		if country != "" {
			m.allowedPerCountry[country]++
		}
		if host != "" {
			m.allowedPerHost[host]++
		}
	}
}

func (m *Metrics) RecordBlockedRequest(country, host string) {
	if country != "" || host != "" {
		m.mu.Lock()
		defer m.mu.Unlock()
		if country != "" {
			m.blockedPerCountry[country]++
		}
		if host != "" {
			m.blockedPerHost[host]++
		}
	}
}

func (m *Metrics) RecordAllowedHost(host string) {
	if host != "" {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.allowedPerHost[host]++
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

func (m *Metrics) GetCountryStats() (blocked map[string]int64, allowed map[string]int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create copies to avoid races
	blockedCopy := make(map[string]int64)
	for k, v := range m.blockedPerCountry {
		blockedCopy[k] = v
	}

	allowedCopy := make(map[string]int64)
	for k, v := range m.allowedPerCountry {
		allowedCopy[k] = v
	}

	return blockedCopy, allowedCopy
}

func (m *Metrics) GetHostStats() (blocked map[string]int64, allowed map[string]int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create copies to avoid races
	blockedCopy := make(map[string]int64)
	for k, v := range m.blockedPerHost {
		blockedCopy[k] = v
	}

	allowedCopy := make(map[string]int64)
	for k, v := range m.allowedPerHost {
		allowedCopy[k] = v
	}

	return blockedCopy, allowedCopy
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	internal, cacheHits, cacheMisses, geoipNodeCount, geoipBuildEpoch := metrics.GetStats()
	blockedPerCountry, allowedPerCountry := metrics.GetCountryStats()
	blockedPerHost, allowedPerHost := metrics.GetHostStats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Write Prometheus metrics in text format
	fmt.Fprintf(w, "# HELP accepted_internal_total Counter of internal network requests accepted\n")
	fmt.Fprintf(w, "# TYPE accepted_internal_total counter\n")
	fmt.Fprintf(w, "accepted_internal_total %d\n\n", internal)

	fmt.Fprintf(w, "# HELP cache_hits_total Counter of cache hits\n")
	fmt.Fprintf(w, "# TYPE cache_hits_total counter\n")
	fmt.Fprintf(w, "cache_hits_total %d\n\n", cacheHits)

	fmt.Fprintf(w, "# HELP cache_misses_total Counter of cache misses\n")
	fmt.Fprintf(w, "# TYPE cache_misses_total counter\n")
	fmt.Fprintf(w, "cache_misses_total %d\n\n", cacheMisses)

	fmt.Fprintf(w, "# HELP geoip_node_count Total number of nodes in GeoIP database\n")
	fmt.Fprintf(w, "# TYPE geoip_node_count gauge\n")
	fmt.Fprintf(w, "geoip_node_count %d\n\n", geoipNodeCount)

	fmt.Fprintf(w, "# HELP geoip_build_timestamp GeoIP database build timestamp in milliseconds\n")
	fmt.Fprintf(w, "# TYPE geoip_build_timestamp gauge\n")
	fmt.Fprintf(w, "geoip_build_timestamp{date=\"%s\"} %d\n\n", geoipBuildEpoch.Format(time.RFC3339), geoipBuildEpoch.UnixMilli())

	if len(allowedPerCountry) > 0 {
		fmt.Fprintf(w, "# HELP accepted_country_total Counter of requests accepted per country\n")
		fmt.Fprintf(w, "# TYPE accepted_country_total counter\n")
		for country, count := range allowedPerCountry {
			fmt.Fprintf(w, "accepted_country_total{country=\"%s\"} %d\n", country, count)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(blockedPerCountry) > 0 {
		fmt.Fprintf(w, "# HELP blocked_country_total Counter of requests blocked per country\n")
		fmt.Fprintf(w, "# TYPE blocked_country_total counter\n")
		for country, count := range blockedPerCountry {
			fmt.Fprintf(w, "blocked_country_total{country=\"%s\"} %d\n", country, count)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(allowedPerHost) > 0 {
		fmt.Fprintf(w, "# HELP accepted_host_total Counter of requests accepted per host\n")
		fmt.Fprintf(w, "# TYPE accepted_host_total counter\n")
		for host, count := range allowedPerHost {
			fmt.Fprintf(w, "accepted_host_total{host=\"%s\"} %d\n", host, count)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(blockedPerHost) > 0 {
		fmt.Fprintf(w, "# HELP blocked_host_total Counter of requests blocked per host\n")
		fmt.Fprintf(w, "# TYPE blocked_host_total counter\n")
		for host, count := range blockedPerHost {
			fmt.Fprintf(w, "blocked_host_total{host=\"%s\"} %d\n", host, count)
		}
	}
}
