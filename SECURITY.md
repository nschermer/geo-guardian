# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Geo Guardian, please report it responsibly by emailing security details to the maintainers rather than disclosing it publicly. We ask that you:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. **Do not** include sensitive information in public comments
3. Allow reasonable time for the maintainers to investigate and release a fix before public disclosure

Please include the following information in your report:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if you have one)

## Security Considerations

### GeoIP Database Updates

- The MaxMind GeoLite2 Country database should be kept up-to-date for accurate geolocation
- Geo Guardian automatically reloads the database every 15 minutes without requiring restarts
- Use MaxMind's [geoipupdate](https://github.com/maxmind/geoipupdate) utility to automate database updates
- Old databases may contain inaccurate or outdated geolocation information

### Network Security

- **ForwardAuth Middleware**: Geo Guardian is designed as a ForwardAuth middleware for Traefik
- Ensure that only your reverse proxy can reach the service directly
- Do not expose Geo Guardian's port directly to the internet
- Configure appropriate firewall rules to restrict access to the service

### IP Range Validation

- Local IP ranges should be configured carefully to prevent authorization bypass
- Review your allowlist regularly to ensure only intended networks are permitted
- Be cautious when adding overly broad CIDR ranges (e.g., 0.0.0.0/0)

### Metrics Endpoint

- The Prometheus metrics endpoint (`/metrics`) exposes statistics including:
  - Request counts by country and host
  - Cache performance data
  - Decision statistics
- Consider restricting access to the metrics endpoint to monitoring systems only
- Do not expose the metrics endpoint publicly if it contains sensitive information

### Container Security

- Run the container with the least privileges necessary
- Use read-only root filesystem when possible
- Do not run as root in production environments
- Regularly rebuild containers to receive upstream security patches
- Scan images for vulnerabilities using tools like Trivy or similar

### Data Privacy

- Geo Guardian performs geolocation lookups based on IP addresses
- No personally identifiable information (PII) is stored by Geo Guardian itself
- Ensure compliance with applicable privacy regulations (GDPR, CCPA, etc.) regarding IP logging
- Review your Traefik and access logs for sensitive information

## Supported Versions

Security updates are provided for:
- **Current major version**: Full support
- **Previous major versions**: Limited support for critical security issues

We recommend users upgrade to the latest version to receive all security improvements.

## Security Best Practices

1. **Keep dependencies up-to-date**: Regularly rebuild containers to receive Go runtime and Alpine Linux security updates
2. **Use environment variables**: Store sensitive configuration in environment variables, not in code or containers
3. **Enable logging**: Configure appropriate logging to detect and investigate suspicious activity
4. **Monitor metrics**: Set up alerts on Prometheus metrics for unusual access patterns
5. **Regular audits**: Periodically review your configuration and access patterns
6. **Network isolation**: Isolate Geo Guardian and your applications within a secure network segment

## Known Limitations

- Geolocation accuracy depends on the MaxMind database quality and frequency of updates
- Requests from VPNs, proxies, or Tor exit nodes may appear to originate from different countries
- Reserved and private IP ranges are handled according to MaxMind's database
- Database reloads happen automatically every 15 minutes; changes may not be immediate

## Third-Party Dependencies

Geo Guardian depends on:
- **Go standard library**: Keep your Go runtime up-to-date
- **MaxMind GeoLite2 database**: Comply with MaxMind's license terms
- **Alpine Linux** (in Docker): Subscribe to Alpine security advisories

Review the `go.mod` file for all Go dependencies and check for security advisories using:
```bash
go list -u -m all
go mod tidy
```

## Security Changelog

See the GitHub releases for security-related updates and fixes.

## Questions or Concerns?

If you have general security questions about Geo Guardian's architecture or design, please open a discussion on GitHub or check the [README](README.md) for more information.
