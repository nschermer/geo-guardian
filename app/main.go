package main

import (
	"context"
	"fmt"
	"hash/maphash"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// GeoIPDB manages the GeoIP database reader with safe reloading
type GeoIPDB struct {
	mu      sync.RWMutex
	path    string
	reader  *maxminddb.Reader
	modTime time.Time
}

// geoIPRecord holds only the fields we use. Decoding into this instead of the
// full geoip2 Country record skips the localized names and avoids allocating.
type geoIPRecord struct {
	Country struct {
		ISOCode           string `maxminddb:"iso_code"`
		IsInEuropeanUnion bool   `maxminddb:"is_in_european_union"`
	} `maxminddb:"country"`
}

// cacheShards must be a power of two.
const cacheShards = 32

// CountryCache is a sharded cache for country lookups. Hits only take a shard
// read lock, so they scale across cores; when a shard is full an arbitrary
// entry is evicted.
type CountryCache struct {
	shards   [cacheShards]cacheShard
	perShard int
	seed     maphash.Seed
}

type cacheShard struct {
	mu sync.RWMutex
	m  map[netip.Addr]CountryInfo
	_  [32]byte // pad to a cache line to avoid false sharing between shards
}

// CountryInfo stores GeoIP-derived country information for a lookup
type CountryInfo struct {
	Code string
	InEU bool
}

var (
	// Configuration
	localIPNetworks     []netip.Prefix
	countryCodes        map[string]bool
	blockCountryCodes   map[string]bool
	acceptEuropeanUnion bool
	trustedProxyCount   int
	verboseLogging      bool
	version             = "dev"
	buildDate           = "unknown"

	geoipDB      *GeoIPDB
	countryCache = newCountryCache(1000)
	logger       = log.New(os.Stdout, "", log.LstdFlags)
	metrics      = newMetrics()
)

func newGeoIPDB(path string) *GeoIPDB {
	return &GeoIPDB{
		path: path,
	}
}

func newCountryCache(maxSize int) *CountryCache {
	c := &CountryCache{
		perShard: max(1, (maxSize+cacheShards-1)/cacheShards),
		seed:     maphash.MakeSeed(),
	}
	for i := range c.shards {
		c.shards[i].m = make(map[netip.Addr]CountryInfo, c.perShard)
	}
	return c
}

// shard picks a shard with a seeded hash, so clients can't steer all their
// addresses into one shard.
func (c *CountryCache) shard(ip netip.Addr) *cacheShard {
	return &c.shards[maphash.Comparable(c.seed, ip)&(cacheShards-1)]
}

func (c *CountryCache) Get(ip netip.Addr) (CountryInfo, bool) {
	s := c.shard(ip)
	s.mu.RLock()
	info, found := s.m[ip]
	s.mu.RUnlock()
	return info, found
}

func (c *CountryCache) Set(ip netip.Addr, info CountryInfo) {
	s := c.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.m[ip]; !found && len(s.m) >= c.perShard {
		// Map iteration starts at a random position, so this evicts an
		// arbitrary entry.
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
	s.m[ip] = info
}

func (c *CountryCache) Clear() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		clear(s.m)
		s.mu.Unlock()
	}
}

func (g *GeoIPDB) Load() error {
	// Check file modification time
	fileInfo, err := os.Stat(g.path)
	if err != nil {
		return fmt.Errorf("failed to stat GeoIP2 database: %w", err)
	}

	modTime := fileInfo.ModTime()

	// Skip reload if file hasn't changed
	g.mu.RLock()
	unchanged := !g.modTime.IsZero() && modTime.Equal(g.modTime)
	g.mu.RUnlock()
	if unchanged {
		if verboseLogging {
			logger.Printf("GeoIP2 database unchanged, skipping reload\n")
		}
		return nil
	}

	// Create new reader before closing old one to avoid crashes during reload
	newReader, err := maxminddb.Open(g.path)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP2 database: %w", err)
	}

	// Only Country, City and Enterprise databases have country data (the
	// same set geoip2.Reader.Country accepts).
	dbType := newReader.Metadata.DatabaseType
	if !strings.Contains(dbType, "Country") && !strings.Contains(dbType, "City") && !strings.Contains(dbType, "Enterprise") {
		newReader.Close()
		return fmt.Errorf("unsupported GeoIP2 database type %q: need a Country, City or Enterprise database", dbType)
	}

	g.mu.Lock()
	oldReader := g.reader
	g.reader = newReader
	g.modTime = modTime
	g.mu.Unlock()

	if oldReader != nil {
		oldReader.Close()
	}

	// Record GeoIP database node count
	metadata := newReader.Metadata
	var utcTime = time.Unix(int64(metadata.BuildEpoch), 0).UTC()
	metrics.SetGeoIPInfo(metadata.NodeCount, utcTime)

	logger.Printf("GeoIP2 database loaded, build date: %s\n", utcTime.Format(time.RFC3339))

	// Clear cache after reload
	countryCache.Clear()

	return nil
}

func (g *GeoIPDB) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.reader == nil {
		return nil
	}
	err := g.reader.Close()
	g.reader = nil
	return err
}

func getCountryInfo(ip netip.Addr) CountryInfo {
	// Check cache first
	if info, found := countryCache.Get(ip); found {
		metrics.RecordCacheHit()
		return info
	}

	metrics.RecordCacheMiss()

	// Hold RLock for the entire lookup so Load() can safely close the old
	// reader immediately after its write-lock swap completes.
	geoipDB.mu.RLock()
	defer geoipDB.mu.RUnlock()

	if geoipDB.reader == nil {
		return CountryInfo{}
	}

	var record geoIPRecord
	if err := geoipDB.reader.Lookup(ip).Decode(&record); err != nil {
		return CountryInfo{}
	}

	info := CountryInfo{
		Code: record.Country.ISOCode,
		InEU: record.Country.IsInEuropeanUnion,
	}

	// Cache the result
	countryCache.Set(ip, info)

	return info
}

func reloadGeoIPPeriodically(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := geoipDB.Load(); err != nil {
				logger.Printf("Error reloading GeoIP database: %v\n", err)
			}
		}
	}
}

var sanitizeLogReplacer = strings.NewReplacer("\n", "", "\r", "")

func sanitizeLog(s string) string {
	return sanitizeLogReplacer.Replace(s)
}

func logDecision(action, ip, country, host, reason string) {
	if !verboseLogging {
		return
	}

	logger.Printf("%s ip=%s country=%s host=%s reason=%s",
		strings.ToUpper(action),
		sanitizeLog(ip),
		country,
		sanitizeLog(host),
		reason,
	)
}

// Pre-built responses so the hot path doesn't allocate. The header value
// slices are shared between responses and must never be modified.
var (
	okResponse        = []byte("OK")
	forbiddenResponse = []byte("Forbidden\n")
	textPlainHeader   = []string{"text/plain; charset=utf-8"}
	nosniffHeader     = []string{"nosniff"}
)

func allowResponse(w http.ResponseWriter, country, host string) {
	// Setting Content-Type up front stops net/http from sniffing the body;
	// the value is what sniffing would produce.
	w.Header()["Content-Type"] = textPlainHeader
	w.WriteHeader(http.StatusOK)
	w.Write(okResponse)
	metrics.RecordAllowedRequest(country, host)
}

// writeForbidden writes the same response as
// http.Error(w, "Forbidden", http.StatusForbidden) without allocating.
func writeForbidden(w http.ResponseWriter) {
	h := w.Header()
	h["Content-Type"] = textPlainHeader
	h["X-Content-Type-Options"] = nosniffHeader
	w.WriteHeader(http.StatusForbidden)
	w.Write(forbiddenResponse)
}

func denyResponse(w http.ResponseWriter, country, host string) {
	writeForbidden(w)
	metrics.RecordBlockedRequest(country, host)
}

// firstHeader returns the first value of a header, like http.Header.Get, but
// skips re-canonicalizing the key. net/http already canonicalizes incoming
// header keys, so key must be given in canonical form.
func firstHeader(h http.Header, key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// clientAddr picks the client address out of an X-Forwarded-For value.
//
// The header lists one address per hop, oldest first. Traefik appends the
// address that connected to it, so the last entry is always trustworthy;
// each trusted proxy in front of Traefik (a CDN or load balancer) adds one
// more trustworthy entry to the right. Everything left of those could have
// been sent by the client, so it is never used. If the header has fewer
// entries than expected, every entry came from a trusted hop and the first
// one is the client.
func clientAddr(forwardedFor string, trustedProxies int) string {
	for {
		idx := strings.LastIndexByte(forwardedFor, ',')
		if idx < 0 {
			return strings.TrimSpace(forwardedFor)
		}
		if trustedProxies == 0 {
			return strings.TrimSpace(forwardedFor[idx+1:])
		}
		trustedProxies--
		forwardedFor = forwardedFor[:idx]
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Traefik sets X-Forwarded-For on the ForwardAuth request; see clientAddr
	// for which entry is trusted.
	forwardedFor := firstHeader(r.Header, "X-Forwarded-For")
	if forwardedFor == "" {
		writeForbidden(w)
		logger.Println("Warning: Missing X-Forwarded-For header")
		logDecision("block", "", "", "", "missing_x_forwarded_for_header")
		return
	}

	ipAddressStr := clientAddr(forwardedFor, trustedProxyCount)

	// Extract requested host from X-Forwarded-Host header
	requestedHost := firstHeader(r.Header, "X-Forwarded-Host")

	// Parse the IP address
	ipAddress, err := netip.ParseAddr(ipAddressStr)
	if err != nil {
		writeForbidden(w)
		logger.Println("Warning: Invalid IP address in X-Forwarded-For header")
		logDecision("block", ipAddressStr, "", requestedHost, "invalid_ip")
		return
	}

	// Check if IP overlaps with LOCAL_IP_NETWORKS
	for _, prefix := range localIPNetworks {
		if prefix.Contains(ipAddress) {
			allowResponse(w, "", requestedHost)
			metrics.RecordInternalRequest()
			logDecision("allow", ipAddressStr, "", requestedHost, "local_network")
			return
		}
	}

	// Skip GeoIP lookup only when no country codes or EU acceptance or block list are configured
	if len(countryCodes) == 0 && !acceptEuropeanUnion && len(blockCountryCodes) == 0 {
		denyResponse(w, "", requestedHost)
		logDecision("block", ipAddressStr, "", requestedHost, "no_rules_configured")
		return
	}

	// Get country info from GeoIP2 with caching
	countryInfo := getCountryInfo(ipAddress)
	countryCode := countryInfo.Code

	if countryCode == "" {
		denyResponse(w, "", requestedHost)
		logDecision("block", ipAddressStr, "", requestedHost, "unknown_country")
		return
	}

	// Block mode: reject if country is in BLOCK_COUNTRY_CODES
	if len(blockCountryCodes) > 0 {
		if blockCountryCodes[countryCode] {
			denyResponse(w, countryCode, requestedHost)
			logDecision("block", ipAddressStr, countryCode, requestedHost, "blocked_country")
			return
		}
		// If not in block list, allow
		allowResponse(w, countryCode, requestedHost)
		logDecision("allow", ipAddressStr, countryCode, requestedHost, "not_in_block_list")
		return
	}

	// Accept EU members when the feature flag is enabled
	// Check if country is in ACCEPT_COUNTRY_CODES
	if (acceptEuropeanUnion && countryInfo.InEU) || countryCodes[countryCode] {
		allowResponse(w, countryCode, requestedHost)
		if acceptEuropeanUnion && countryInfo.InEU {
			logDecision("allow", ipAddressStr, countryCode, requestedHost, "eu_member")
		} else {
			logDecision("allow", ipAddressStr, countryCode, requestedHost, "allowed_country")
		}
		return
	}

	// No match found
	denyResponse(w, countryCode, requestedHost)
	logDecision("block", ipAddressStr, countryCode, requestedHost, "not_allowed")
}

func parseLocalIPs(localIPsStr string) error {
	if localIPsStr == "" {
		return nil
	}

	for _, ipRange := range strings.Split(localIPsStr, ",") {
		ipRange = strings.TrimSpace(ipRange)
		if ipRange == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(ipRange)
		if err != nil {
			logger.Printf("Warning: Invalid IP range '%s': %v\n", ipRange, err)
			continue
		}

		localIPNetworks = append(localIPNetworks, prefix)
	}

	// Sort prefixes by size (larger masks first) for faster matching
	slices.SortFunc(localIPNetworks, func(a, b netip.Prefix) int {
		return b.Bits() - a.Bits()
	})

	return nil
}

func parseCountryCodeList(countryCodesStr string, logLabel string) (map[string]bool, error) {
	result := make(map[string]bool)

	if countryCodesStr == "" {
		return result, nil
	}

	var invalidCodes []string
	var validCountries []string

	for _, code := range strings.Split(countryCodesStr, ",") {
		code = strings.TrimSpace(strings.ToUpper(code))
		if code == "" {
			continue
		}

		countryName, valid := validCountryCodes[code]
		if !valid {
			invalidCodes = append(invalidCodes, code)
		} else {
			result[code] = true
			validCountries = append(validCountries, fmt.Sprintf("%s (%s)", countryName, code))
		}
	}

	if len(invalidCodes) > 0 {
		return nil, fmt.Errorf("invalid ISO 3166-1 alpha-2 country codes: %s", strings.Join(invalidCodes, ", "))
	}

	if len(validCountries) > 0 {
		logger.Printf("%s countries: %s\n", logLabel, strings.Join(validCountries, ", "))
	}

	return result, nil
}

func parseCountryCodes(countryCodesStr string) error {
	var err error
	countryCodes, err = parseCountryCodeList(countryCodesStr, "Allowed")
	return err
}

func parseBlockCountryCodes(countryCodesStr string) error {
	var err error
	blockCountryCodes, err = parseCountryCodeList(countryCodesStr, "Blocked")
	return err
}

func parseBoolEnv(key string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return value == "1" || value == "true" || value == "t" || value == "yes" || value == "y" || value == "on"
}

// parseCountEnv reads a non-negative integer, returning 0 when unset.
func parseCountEnv(key string) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", key, value)
	}
	return n, nil
}

func main() {
	// Read environment variables
	localIPsStr := os.Getenv("LOCAL_IPS")
	if localIPsStr == "" {
		localIPsStr = "192.168.0.0/16,10.0.0.0/8,127.0.0.0/8,fd00::/8"
	}

	countryCodesStr := os.Getenv("ACCEPT_COUNTRY_CODES")
	blockCountryCodesStr := os.Getenv("BLOCK_COUNTRY_CODES")
	geoip2DBPath := os.Getenv("GEOIP2_DB")
	acceptEuropeanUnion = parseBoolEnv("ACCEPT_EUROPEAN_UNION")

	// Read host address, default to :80
	hostAddr := os.Getenv("HOST_ADDR")
	if hostAddr == "" {
		hostAddr = ":80"
	}

	verboseLogging = parseBoolEnv("VERBOSE")

	logger.Printf("Geo Guardian version %s (%s)", version, buildDate)

	var err error
	if trustedProxyCount, err = parseCountEnv("TRUSTED_PROXY_COUNT"); err != nil {
		logger.Fatalf("Error parsing TRUSTED_PROXY_COUNT: %v\n", err)
	}
	if trustedProxyCount > 0 {
		logger.Printf("Trusting %d proxy hop(s) in front of Traefik in X-Forwarded-For\n", trustedProxyCount)
	}

	// Validate mutual exclusivity
	if blockCountryCodesStr != "" && (countryCodesStr != "" || acceptEuropeanUnion) {
		logger.Fatal("BLOCK_COUNTRY_CODES cannot be used with ACCEPT_COUNTRY_CODES or ACCEPT_EUROPEAN_UNION")
	}

	if countryCodesStr == "" && !acceptEuropeanUnion && blockCountryCodesStr == "" {
		logger.Println("Warning: No country filtering configured (ACCEPT_COUNTRY_CODES, ACCEPT_EUROPEAN_UNION, or BLOCK_COUNTRY_CODES)")
	}

	// Validate GEOIP2_DB path
	if geoip2DBPath == "" {
		logger.Fatal("GEOIP2_DB environment variable is not set")
	}

	if _, err := os.Stat(geoip2DBPath); os.IsNotExist(err) {
		logger.Fatalf("GeoIP2 database file not found: %s\n", geoip2DBPath)
	}

	// Parse configuration
	if err := parseLocalIPs(localIPsStr); err != nil {
		logger.Fatalf("Error parsing LOCAL_IPS: %v\n", err)
	}

	if err := parseCountryCodes(countryCodesStr); err != nil {
		logger.Fatalf("Error parsing ACCEPT_COUNTRY_CODES: %v\n", err)
	}

	if err := parseBlockCountryCodes(blockCountryCodesStr); err != nil {
		logger.Fatalf("Error parsing BLOCK_COUNTRY_CODES: %v\n", err)
	}

	if acceptEuropeanUnion {
		logger.Println("Accepting requests from EU member countries")
	}

	// Initialize and load GeoIP database
	geoipDB = newGeoIPDB(geoip2DBPath)
	if err := geoipDB.Load(); err != nil {
		logger.Fatalf("Error loading GeoIP database: %v\n", err)
	}
	defer geoipDB.Close()

	// Start periodic reload in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reloadGeoIPPeriodically(ctx)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/metrics", metricsHandler)

	server := &http.Server{
		Addr:           hostAddr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    5 * time.Second,
		MaxHeaderBytes: 1 << 14, // 16 KB request header limit
	}

	// Handle graceful shutdown. ListenAndServe returns as soon as Shutdown
	// starts, so main waits on shutdownDone for in-flight requests to drain.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		logger.Println("Shutting down server...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Printf("Server shutdown error: %v\n", err)
		}
	}()

	logger.Printf("Starting server on %s\n", hostAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Server error: %v\n", err)
	}
	<-shutdownDone
}
