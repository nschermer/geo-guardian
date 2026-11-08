package main

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

var benchSetupOnce sync.Once

// benchSetup loads the bundled GeoLite2 database and an allow-list config.
func benchSetup(b *testing.B) {
	b.Helper()
	benchSetupOnce.Do(func() {
		logger.SetOutput(io.Discard)
		verboseLogging = false
		localIPNetworks = nil
		if err := parseLocalIPs("192.168.0.0/16,10.0.0.0/8,127.0.0.0/8,fd00::/8"); err != nil {
			panic(err)
		}
		if err := parseCountryCodes("NL,BE,DE"); err != nil {
			panic(err)
		}
		acceptEuropeanUnion = false
		blockCountryCodes = map[string]bool{}
		geoipDB = newGeoIPDB("GeoLite2-Country.mmdb")
		if err := geoipDB.Load(); err != nil {
			panic(err)
		}
	})
}

// discardWriter is a minimal ResponseWriter so the benchmark measures the
// handler rather than httptest.ResponseRecorder.
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardWriter) WriteHeader(int)             {}

func randomPublicIPs(n int, seed uint64) []string {
	r := rand.New(rand.NewPCG(seed, seed))
	ips := make([]string, n)
	for i := range ips {
		ips[i] = fmt.Sprintf("%d.%d.%d.%d", r.IntN(223)+1, r.IntN(256), r.IntN(256), r.IntN(254)+1)
	}
	return ips
}

func newBenchRequest(ip string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", ip+", 10.0.0.1")
	req.Header.Set("X-Forwarded-Host", "example.com")
	return req
}

func runHandlerBench(b *testing.B, ips []string) {
	reqs := make([]*http.Request, len(ips))
	for i, ip := range ips {
		reqs[i] = newBenchRequest(ip)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := &discardWriter{h: make(http.Header)}
		i := rand.IntN(len(reqs))
		for pb.Next() {
			clear(w.h)
			indexHandler(w, reqs[i%len(reqs)])
			i++
		}
	})
}

// Local network: no GeoIP lookup at all.
func BenchmarkHandlerLocal(b *testing.B) {
	benchSetup(b)
	runHandlerBench(b, []string{"192.168.1.10", "10.1.2.3", "127.0.0.1"})
}

// Small working set that always fits in the 1000-entry LRU cache.
func BenchmarkHandlerCacheHit(b *testing.B) {
	benchSetup(b)
	ips := randomPublicIPs(500, 1)
	for _, ip := range ips {
		getCountryInfo(netip.MustParseAddr(ip))
	}
	runHandlerBench(b, ips)
}

// Large working set: almost every request misses the cache.
func BenchmarkHandlerCacheMiss(b *testing.B) {
	benchSetup(b)
	runHandlerBench(b, randomPublicIPs(200_000, 2))
}

func BenchmarkGeoIPLookupUncached(b *testing.B) {
	benchSetup(b)
	ips := randomPublicIPs(100_000, 3)
	addrs := make([]netip.Addr, len(ips))
	for i, ip := range ips {
		addrs[i] = netip.MustParseAddr(ip)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := rand.IntN(len(addrs))
		var rec geoIPRecord
		for pb.Next() {
			geoipDB.mu.RLock()
			_ = geoipDB.reader.Lookup(addrs[i%len(addrs)]).Decode(&rec)
			geoipDB.mu.RUnlock()
			i++
		}
	})
}

func BenchmarkCountryCacheGet(b *testing.B) {
	c := newCountryCache(1000)
	addrs := make([]netip.Addr, 1000)
	for i, ip := range randomPublicIPs(1000, 4) {
		addrs[i] = netip.MustParseAddr(ip)
		c.Set(addrs[i], CountryInfo{Code: "NL"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := rand.IntN(len(addrs))
		for pb.Next() {
			c.Get(addrs[i%len(addrs)])
			i++
		}
	})
}

func BenchmarkMetricsRecord(b *testing.B) {
	m := newMetrics()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.RecordAllowedRequest("NL", "example.com")
		}
	})
}

func BenchmarkMetricsHandler(b *testing.B) {
	benchSetup(b)
	for i := range 5000 {
		host := fmt.Sprintf("host-%d.example.com", i)
		metrics.RecordAllowedRequest("NL", host)
		metrics.RecordBlockedRequest("US", host)
	}
	for code := range validCountryCodes {
		metrics.RecordBlockedRequest(code, "")
	}
	req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	w := &discardWriter{h: make(http.Header)}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		metricsHandler(w, req)
	}
}

// Full HTTP round-trip over loopback, for comparing handler cost with
// net/http overhead.
func BenchmarkHTTPEndToEnd(b *testing.B) {
	benchSetup(b)
	ips := randomPublicIPs(500, 1)
	for _, ip := range ips {
		getCountryInfo(netip.MustParseAddr(ip))
	}
	srv := httptest.NewServer(http.HandlerFunc(indexHandler))
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := rand.IntN(len(ips))
		for pb.Next() {
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			req.Header.Set("X-Forwarded-For", ips[i%len(ips)])
			req.Header.Set("X-Forwarded-Host", "example.com")
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			i++
		}
	})
}
