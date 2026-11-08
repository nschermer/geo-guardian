package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientAddr(t *testing.T) {
	cases := []struct {
		xff     string
		trusted int
		want    string
	}{
		{"1.2.3.4", 0, "1.2.3.4"},
		{" 1.2.3.4 ", 0, "1.2.3.4"},
		// Client-supplied entry on the left must be ignored.
		{"10.0.0.1, 1.2.3.4", 0, "1.2.3.4"},
		{"10.0.0.1,1.2.3.4", 0, "1.2.3.4"},
		// One trusted proxy in front: skip its entry.
		{"1.2.3.4, 203.0.113.9", 1, "1.2.3.4"},
		{"10.0.0.1, 1.2.3.4, 203.0.113.9", 1, "1.2.3.4"},
		// Two trusted proxies.
		{"1.2.3.4, 203.0.113.9, 203.0.113.10", 2, "1.2.3.4"},
		// Fewer entries than trusted proxies: all entries are trusted, so
		// the first one is the client.
		{"1.2.3.4", 3, "1.2.3.4"},
		{"1.2.3.4, 203.0.113.9", 3, "1.2.3.4"},
		// Degenerate values are returned as-is for ParseAddr to reject.
		{"", 0, ""},
		{"1.2.3.4,", 0, ""},
		{",", 0, ""},
	}
	for _, c := range cases {
		if got := clientAddr(c.xff, c.trusted); got != c.want {
			t.Errorf("clientAddr(%q, %d) = %q, want %q", c.xff, c.trusted, got, c.want)
		}
	}
}

func setupHandlerTest(t *testing.T) *httptest.Server {
	t.Helper()
	logger.SetOutput(io.Discard)
	localIPNetworks = nil
	if err := parseLocalIPs("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if err := parseCountryCodes("NL"); err != nil {
		t.Fatal(err)
	}
	acceptEuropeanUnion = false
	blockCountryCodes = map[string]bool{}
	geoipDB = newGeoIPDB("GeoLite2-Country.mmdb")
	if err := geoipDB.Load(); err != nil {
		t.Skipf("GeoLite2-Country.mmdb not available: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(indexHandler))
	t.Cleanup(srv.Close)
	return srv
}

func TestIndexHandlerForwardedFor(t *testing.T) {
	srv := setupHandlerTest(t)

	const (
		local = "10.0.0.1"
		nl    = "145.53.0.1" // KPN, Netherlands
		us    = "8.8.8.8"
	)

	cases := []struct {
		name    string
		xff     string
		trusted int
		want    int
	}{
		{"missing header", "", 0, http.StatusForbidden},
		{"invalid address", "not-an-ip", 0, http.StatusForbidden},
		{"local", local, 0, http.StatusOK},
		{"allowed country", nl, 0, http.StatusOK},
		{"blocked country", us, 0, http.StatusForbidden},
		// A client prepending a local or allowed address must not get in.
		{"spoofed local first", local + ", " + us, 0, http.StatusForbidden},
		{"spoofed allowed first", nl + ", " + us, 0, http.StatusForbidden},
		// With a trusted proxy in front, its entry is skipped.
		{"behind one proxy", nl + ", " + us, 1, http.StatusOK},
		{"spoof behind one proxy", local + ", " + us + ", " + nl, 1, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trustedProxyCount = c.trusted
			t.Cleanup(func() { trustedProxyCount = 0 })
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("X-Forwarded-For %q (trusted=%d): got %d, want %d", c.xff, c.trusted, resp.StatusCode, c.want)
			}
		})
	}
}
