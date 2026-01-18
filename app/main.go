package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
)

// GeoIPDB manages the GeoIP database reader with safe reloading
type GeoIPDB struct {
	mu      sync.RWMutex
	path    string
	reader  *geoip2.Reader
	modTime time.Time
}

// CountryCache implements a lazy cache for country code lookups
type CountryCache struct {
	mu      sync.RWMutex
	cache   map[string]CountryInfo
	maxSize int
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
	verboseLogging      bool

	geoipDB      *GeoIPDB
	countryCache = newCountryCache(1000)
	logger       = log.New(os.Stdout, "", log.LstdFlags)
	metrics      = &Metrics{
		blockedPerCountry: make(map[string]int64),
		allowedPerCountry: make(map[string]int64),
		blockedPerHost:    make(map[string]int64),
		allowedPerHost:    make(map[string]int64),
	}
)

func newGeoIPDB(path string) *GeoIPDB {
	return &GeoIPDB{
		path: path,
	}
}

func newCountryCache(maxSize int) *CountryCache {
	return &CountryCache{
		cache:   make(map[string]CountryInfo),
		maxSize: maxSize,
	}
}

func (c *CountryCache) Get(ip string) (CountryInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, found := c.cache[ip]
	return info, found
}

func (c *CountryCache) Set(ip string, info CountryInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: clear cache when it exceeds maxSize
	if len(c.cache) >= c.maxSize {
		c.cache = make(map[string]CountryInfo)
		metrics.RecordCacheReset()
	}

	c.cache[ip] = info
}

func (c *CountryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	metrics.RecordCacheReset()
	if len(c.cache) > 0 {
		metrics.RecordCacheReset()
	}

	c.cache = make(map[string]CountryInfo)
}

func (g *GeoIPDB) Load() error {
	// Check file modification time
	fileInfo, err := os.Stat(g.path)
	if err != nil {
		return fmt.Errorf("failed to stat GeoIP2 database: %w", err)
	}

	modTime := fileInfo.ModTime()

	// Skip reload if file hasn't changed
	if !g.modTime.IsZero() && modTime.Equal(g.modTime) {
		logger.Printf("GeoIP2 database unchanged, skipping reload\n")
		return nil
	}

	// Create new reader before closing old one to avoid crashes during reload
	newReader, err := geoip2.Open(g.path)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP2 database: %w", err)
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
	metadata := newReader.Metadata()
	metrics.SetGeoIPInfo(metadata.NodeCount, metadata.BuildEpoch)

	logger.Printf("GeoIP2 database loaded at %s\n", time.Now().Format(time.RFC3339))

	// Clear cache after reload
	countryCache.Clear()

	return nil
}

func (g *GeoIPDB) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.reader != nil {
		return g.reader.Close()
	}
	return nil
}

func getCountryInfo(ip netip.Addr) CountryInfo {
	ipStr := ip.String()

	// Check cache first
	if info, found := countryCache.Get(ipStr); found {
		metrics.RecordCacheHit()
		return info
	}

	metrics.RecordCacheMiss()

	geoipDB.mu.RLock()
	reader := geoipDB.reader
	geoipDB.mu.RUnlock()

	if reader == nil {
		return CountryInfo{}
	}

	record, err := reader.Country(ip)
	if err != nil {
		return CountryInfo{}
	}

	info := CountryInfo{
		Code: record.Country.ISOCode,
		InEU: record.Country.IsInEuropeanUnion,
	}

	// Cache the result
	countryCache.Set(ipStr, info)

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

func logDecision(action, ip, country, host, reason string) {
	if !verboseLogging {
		return
	}

	logger.Printf("%s ip=%s country=%s host=%s reason=%s", strings.ToUpper(action), ip, country, host, reason)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Read IP address from X-Forwarded-For header
	// Handle comma-separated list, take first IP (actual client)
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logger.Println("Warning: Missing X-Forwarded-For header")
		logDecision("block", "", "", "", "missing_x_forwarded_for_header")
		return
	}

	// Extract requested host from X-Forwarded-Host header
	requestedHost := r.Header.Get("X-Forwarded-Host")

	ipAddressStr := strings.TrimSpace(strings.Split(forwardedFor, ",")[0])

	// Parse the IP address
	ipAddress, err := netip.ParseAddr(ipAddressStr)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logger.Printf("Warning: Invalid IP address received: %s\n", ipAddressStr)
		logDecision("block", ipAddressStr, "", requestedHost, "invalid_ip")
		return
	}

	// Check if IP overlaps with LOCAL_IP_NETWORKS
	for _, prefix := range localIPNetworks {
		if prefix.Contains(ipAddress) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			metrics.RecordInternalRequest()
			metrics.RecordAllowedRequest("", requestedHost)
			logDecision("allow", ipAddressStr, "", requestedHost, "local_network")
			return
		}
	}

	// Skip GeoIP lookup only when no country codes or EU acceptance or block list are configured
	if len(countryCodes) == 0 && !acceptEuropeanUnion && len(blockCountryCodes) == 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		metrics.RecordBlockedRequest("", requestedHost)
		logDecision("block", ipAddressStr, "", requestedHost, "no_rules_configured")
		return
	}

	// Get country info from GeoIP2 with caching
	countryInfo := getCountryInfo(ipAddress)
	countryCode := countryInfo.Code

	if countryCode == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		metrics.RecordBlockedRequest("", requestedHost)
		logDecision("block", ipAddressStr, "", requestedHost, "unknown_country")
		return
	}

	// Block mode: reject if country is in BLOCK_COUNTRY_CODES
	if len(blockCountryCodes) > 0 {
		if blockCountryCodes[countryCode] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			metrics.RecordBlockedRequest(countryCode, requestedHost)
			logDecision("block", ipAddressStr, countryCode, requestedHost, "blocked_country")
			return
		}
		// If not in block list, allow
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		metrics.RecordAllowedRequest(countryCode, requestedHost)
		logDecision("allow", ipAddressStr, countryCode, requestedHost, "not_in_block_list")
		return
	}

	// Accept EU members when the feature flag is enabled
	// Check if country is in ACCEPT_COUNTRY_CODES
	if (acceptEuropeanUnion && countryInfo.InEU) || countryCodes[countryCode] {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		metrics.RecordAllowedRequest(countryCode, requestedHost)
		if acceptEuropeanUnion && countryInfo.InEU {
			logDecision("allow", ipAddressStr, countryCode, requestedHost, "eu_ember")
		} else {
			logDecision("allow", ipAddressStr, countryCode, requestedHost, "allowed_country")
		}
		return
	}

	// No match found
	http.Error(w, "Forbidden", http.StatusForbidden)
	metrics.RecordBlockedRequest(countryCode, requestedHost)
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

	return nil
}

func parseCountryCodes(countryCodesStr string) error {
	countryCodes = make(map[string]bool)

	if countryCodesStr == "" {
		return nil
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
			countryCodes[code] = true
			validCountries = append(validCountries, fmt.Sprintf("%s (%s)", countryName, code))
		}
	}

	if len(invalidCodes) > 0 {
		return fmt.Errorf("invalid ISO 3166-1 alpha-2 country codes: %s", strings.Join(invalidCodes, ", "))
	}

	if len(validCountries) > 0 {
		logger.Printf("Allowed countries: %s\n", strings.Join(validCountries, ", "))
	}

	return nil
}

func parseBlockCountryCodes(countryCodesStr string) error {
	blockCountryCodes = make(map[string]bool)

	if countryCodesStr == "" {
		return nil
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
			blockCountryCodes[code] = true
			validCountries = append(validCountries, fmt.Sprintf("%s (%s)", countryName, code))
		}
	}

	if len(invalidCodes) > 0 {
		return fmt.Errorf("invalid ISO 3166-1 alpha-2 country codes: %s", strings.Join(invalidCodes, ", "))
	}

	if len(validCountries) > 0 {
		logger.Printf("Blocked countries: %s\n", strings.Join(validCountries, ", "))
	}

	return nil
}

func parseBoolEnv(key string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return value == "1" || value == "true" || value == "t" || value == "yes" || value == "y" || value == "on"
}

func main() {
	// Read environment variables
	localIPsStr := os.Getenv("LOCAL_IPS")
	if localIPsStr == "" {
		localIPsStr = "192.168.0.0/16,10.0.0.0/8,127.0.0.0/8"
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

	// Validate mutual exclusivity
	if blockCountryCodesStr != "" && (countryCodesStr != "" || acceptEuropeanUnion) {
		logger.Fatal("BLOCK_COUNTRY_CODES cannot be used with ACCEPT_COUNTRY_CODES or ACCEPT_EUROPEAN_UNION")
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
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/metrics", metricsHandler)

	server := &http.Server{
		Addr:         hostAddr,
		Handler:      nil,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
	}

	// Handle graceful shutdown
	go func() {
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
}
