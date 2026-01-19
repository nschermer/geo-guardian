# 🛡️ Geo Guardian

A high-performance GeoIP-based access control service written in Go.

This container is intended for use as a **ForwardAuth middleware in Traefik**, enabling geo-location based access control for your applications. See [Traefik ForwardAuth documentation](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/) for integration details.

## 🎯 Overview

This service provides IP-based access control using GeoIP lookups and local IP allowlisting. It checks incoming requests against:
1. 🏠 Local IP ranges (configurable)
2. 🌍 Country codes (configurable)

Requests are allowed, or blocked, if they match either criteria.

## ✨ Why Geo Guardian?

### 🚀 **Easier Than Nginx + GeoIP2**
- **No compilation hassles** - Pre-built Docker containers ready to use
- Nginx with GeoIP2 module requires custom builds or hard-to-find pre-built images
- Drop-in solution without complex module compilation

### 🎛️ **Simpler Than Traefik GeoIP Plugins**
- **Straightforward configuration** with environment variables
- No complex plugin installation or middleware chain configuration
- Clean integration via ForwardAuth middleware

### 🔄 **Automated Database Updates**
- **Easy to keep up-to-date** using MaxMind's official update tools
- Automatic database reload every 15 minutes (no restarts needed)
- Compatible with MaxMind's `geoipupdate` utility

### 📊 **Built-in Observability**
- **Native Prometheus metrics** for Grafana integration
- Per-country, per-host statistics out of the box
- Cache performance monitoring included
- No additional plugins or exporters needed

## 🎁 Features

- ⚡ **Fast GeoIP lookups** with intelligent caching (1000 entries)
- 🔄 **Hot database reloads** without restarts (every 15 minutes)
- 🔒 **Thread-safe** concurrent request handling
- 💾 **Minimal footprint** (~15MB Alpine-based container)
- 🌐 **EU support** with single flag for all European Union countries
- 📈 **Prometheus metrics** for monitoring and alerting
- 🎨 **Flexible blocking** - allowlist or blocklist modes

## 🗄️ GeoIP Database

This service is designed to run with the free MaxMind GeoLite2 Country database. Download and update instructions are available in MaxMind's documentation: https://support.maxmind.com/knowledge-base/articles/download-and-update-maxmind-databases
You will need a (free) MaxMind account to obtain an account ID and license key before downloading the database.

## ⚙️ Environment Variables

- `GEOIP2_DB` (required): Path to GeoIP2 database file (e.g., `/data/GeoLite2-Country.mmdb`)
- `HOST_ADDR` (optional): Server host address to listen on
  - Default: `:80`
- `LOCAL_IPS` (optional): Comma-separated list of local IP ranges in CIDR notation
  - Default: `192.168.0.0/16,10.0.0.0/8,127.0.0.0/8`
- `ACCEPT_COUNTRY_CODES` (optional): Comma-separated list of allowed country codes (ISO 3166-1 alpha-2)
  - Example: `US,CA,GB,DE`
- `ACCEPT_EUROPEAN_UNION` (optional): When set to a truthy value (`true`, `1`, `yes`), allows any country flagged as part of the EU by GeoIP (`IsInEuropeanUnion`)
- `BLOCK_COUNTRY_CODES` (optional): Comma-separated list of blocked country codes (ISO 3166-1 alpha-2)
  - Example: `CN,RU,US`
  - Cannot be used with `ACCEPT_COUNTRY_CODES` or `ACCEPT_EUROPEAN_UNION` (mutually exclusive)
- `VERBOSE` (optional): Enables verbose logging of allowed and blocked requests
  - Default: `false`

## 🔨 Building

### Native Build

```bash
go build -o geo-guardian *main*.go
```

### Docker Build

```bash
docker build -f Dockerfile -t geo-guardian:go .
```

## 🚀 Running

### Native

```bash
export GEOIP2_DB=/path/to/GeoLite2-Country.mmdb
export ACCEPT_COUNTRY_CODES=US,CA,GB
export ACCEPT_EUROPEAN_UNION=true
export HOST_ADDR=:8080
./geo-guardian
```

### Docker

```bash
docker run -d \
  -e GEOIP2_DB=/data/GeoLite2-Country.mmdb \
  -e ACCEPT_COUNTRY_CODES=NL,BE,LU \
  -v /path/to/geoip/db:/data \
  geo-guardian:go
```

A sample Docker Compose setup is available at [docker/docker-compose.yml](docker/docker-compose.yml).

## 📊 Benchmark Tool

There is a simple load generator in [benchtool/benchtool.go](benchtool/benchmark.go#L1) that sends 10,000 requests with synthetic `X-Forwarded-For` addresses (10% local-network IPs). Run it against a target server and port to gauge response latency and cache behavior:

```bash
go run ./benchtool/benchtool.go localhost 8080
```

The tool prints mean, median, p99, min, and max latencies for the successful requests.

## 🔌 API

### `GET /`

Checks if the client IP is allowed based on configured rules.

**Request Headers:**
- `X-Forwarded-For`: Client IP address (required)
- `X-Forwarded-Host`: Original requested host (optional, used for host-level metrics/logging)

**Response:**
- `200 OK` with body "OK" - Access allowed
- `403 Forbidden` with body "Forbidden" - Access denied

### `GET /metrics`

Exposes Prometheus-compatible metrics for monitoring.

**Response:**
- Prometheus text format metrics including:
  - `accepted_internal_total` - Counter of internal network requests accepted
  - `cache_hits_total` - Counter of cache hits
  - `cache_misses_total` - Counter of cache misses
  - `cache_resets_total` - Counter of cache resets
  - `geoip_node_count` - Total number of nodes in GeoIP database
  - `accepted_country_total` - Counter of requests accepted per country (only if non-empty)
  - `blocked_country_total` - Counter of requests blocked per country (only if non-empty)
  - `accepted_host_total` - Counter of requests accepted per host (only if non-empty)
  - `blocked_host_total` - Counter of requests blocked per host (only if non-empty)

This endpoint can be scraped by **Prometheus**, **Victoria Metrics**, or any Prometheus-compatible monitoring system.

## 📦 Dependencies

- [geoip2-golang](https://github.com/oschwald/geoip2-golang) - MaxMind GeoIP2 reader

