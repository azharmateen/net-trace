# net-trace

Network debugging CLI: DNS resolution, SSL analysis, HTTP trace timing breakdown.

## Features

- **DNS resolution** with timing across multiple DNS servers
- **SSL/TLS analysis** including certificate chain, cipher suites, expiry
- **HTTP trace** with timing breakdown (DNS, TCP, TLS, TTFB)
- **Security header analysis** with A-F scoring
- **Full trace** combining all checks
- **Multiple output formats**: terminal waterfall, JSON, markdown

## Install

```bash
pip install -e .
```

## Usage

```bash
# DNS resolution
net-trace dns example.com
net-trace dns example.com --type MX

# SSL certificate analysis
net-trace ssl example.com
net-trace ssl example.com --port 8443

# HTTP timing trace
net-trace http https://example.com
net-trace http https://example.com --follow-redirects

# Security headers check
net-trace headers https://example.com

# Full analysis (DNS + SSL + HTTP + headers)
net-trace full example.com

# JSON output
net-trace dns example.com --format json
```

## Security Header Grades

| Grade | Description |
|-------|-------------|
| A | All recommended headers present |
| B | Most headers present, minor gaps |
| C | Some key headers missing |
| D | Several important headers missing |
| F | Critical headers missing (no HSTS, no CSP) |

## License

MIT
