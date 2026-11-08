package main

import (
	"net/netip"
	"sync"
	"testing"
)

func TestCountryCacheGetSet(t *testing.T) {
	c := newCountryCache(100)
	a := netip.MustParseAddr("192.0.2.1")

	if _, ok := c.Get(a); ok {
		t.Fatal("empty cache returned a hit")
	}
	c.Set(a, CountryInfo{Code: "NL", InEU: true})
	if got, ok := c.Get(a); !ok || got != (CountryInfo{Code: "NL", InEU: true}) {
		t.Fatalf("Get = %v, %v", got, ok)
	}
	c.Set(a, CountryInfo{Code: "BE"})
	if got, _ := c.Get(a); got.Code != "BE" {
		t.Fatalf("overwrite: got %q", got.Code)
	}
}

func TestCountryCacheBounded(t *testing.T) {
	c := newCountryCache(64)
	for i := range 10_000 {
		c.Set(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), CountryInfo{Code: "NL"})
	}
	total := 0
	for i := range c.shards {
		n := len(c.shards[i].m)
		if n > c.perShard {
			t.Fatalf("shard %d has %d entries, cap %d", i, n, c.perShard)
		}
		total += n
	}
	if total > cacheShards*c.perShard {
		t.Fatalf("cache holds %d entries, cap %d", total, cacheShards*c.perShard)
	}
}

func TestCountryCacheClear(t *testing.T) {
	c := newCountryCache(100)
	a := netip.MustParseAddr("2001:db8::1")
	c.Set(a, CountryInfo{Code: "NL"})
	c.Clear()
	if _, ok := c.Get(a); ok {
		t.Fatal("entry survived Clear")
	}
	c.Set(a, CountryInfo{Code: "NL"})
	if _, ok := c.Get(a); !ok {
		t.Fatal("Set after Clear did not store")
	}
}

func TestCountryCacheConcurrent(t *testing.T) {
	c := newCountryCache(256)
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 5_000 {
				a := netip.AddrFrom4([4]byte{10, byte(g), byte(i >> 8), byte(i)})
				c.Set(a, CountryInfo{Code: "NL"})
				c.Get(a)
				if i%1000 == 0 {
					c.Clear()
				}
			}
		}()
	}
	wg.Wait()
}
