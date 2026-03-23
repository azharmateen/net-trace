"""DNS resolver: query records, measure resolution time, check propagation."""

from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass, field


# Well-known public DNS servers for propagation checking
DNS_SERVERS = {
    "Google": "8.8.8.8",
    "Google-2": "8.8.4.4",
    "Cloudflare": "1.1.1.1",
    "Cloudflare-2": "1.0.0.1",
    "OpenDNS": "208.67.222.222",
    "Quad9": "9.9.9.9",
}

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV")


@dataclass
class DnsRecord:
    record_type: str
    name: str
    value: str
    ttl: int | None = None


@dataclass
class DnsResult:
    hostname: str
    record_type: str
    records: list[DnsRecord] = field(default_factory=list)
    resolution_time_ms: float = 0.0
    dns_server: str = "system"
    error: str | None = None

    def to_dict(self) -> dict:
        d = {
            "hostname": self.hostname,
            "record_type": self.record_type,
            "dns_server": self.dns_server,
            "resolution_time_ms": round(self.resolution_time_ms, 2),
            "records": [
                {"type": r.record_type, "name": r.name, "value": r.value, "ttl": r.ttl}
                for r in self.records
            ],
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class PropagationResult:
    hostname: str
    record_type: str
    results: dict[str, DnsResult] = field(default_factory=dict)

    @property
    def is_consistent(self) -> bool:
        """Check if all servers return the same records."""
        values = []
        for r in self.results.values():
            if not r.error:
                vals = sorted(rec.value for rec in r.records)
                values.append(tuple(vals))
        return len(set(values)) <= 1

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "record_type": self.record_type,
            "consistent": self.is_consistent,
            "servers": {name: res.to_dict() for name, res in self.results.items()},
        }


def _resolve_with_nslookup(hostname: str, record_type: str, dns_server: str | None = None) -> DnsResult:
    """Use nslookup to resolve DNS records (cross-platform fallback)."""
    result = DnsResult(hostname=hostname, record_type=record_type)

    if dns_server:
        result.dns_server = dns_server

    cmd = ["nslookup"]
    if record_type != "A":
        cmd.extend(["-type=" + record_type])
    cmd.append(hostname)
    if dns_server:
        cmd.append(dns_server)

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        result.resolution_time_ms = (time.monotonic() - start) * 1000
        output = proc.stdout + proc.stderr

        # Parse nslookup output
        lines = output.strip().split("\n")
        in_answer = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Skip server info lines
            if line.startswith("Server:") or line.startswith("Address:") and not in_answer:
                if line.startswith("Address:") and "#" in line:
                    continue
                if line.startswith("Address:"):
                    in_answer = True
                continue

            if "Non-authoritative answer:" in line or "Authoritative answers" in line:
                in_answer = True
                continue

            if in_answer:
                if "name =" in line.lower() or "nameserver =" in line.lower():
                    parts = line.split("=")
                    if len(parts) >= 2:
                        result.records.append(DnsRecord(
                            record_type=record_type,
                            name=hostname,
                            value=parts[-1].strip().rstrip("."),
                        ))
                elif "mail exchanger" in line.lower() or "MX" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        result.records.append(DnsRecord(
                            record_type="MX",
                            name=hostname,
                            value=parts[-1].strip().rstrip("."),
                        ))
                elif "text =" in line.lower():
                    parts = line.split("=", 1)
                    if len(parts) >= 2:
                        result.records.append(DnsRecord(
                            record_type="TXT",
                            name=hostname,
                            value=parts[-1].strip().strip('"'),
                        ))
                elif "Address:" in line or "address" in line.lower():
                    val = line.split(":")[-1].strip() if ":" in line else line.split()[-1]
                    if val and val != hostname:
                        result.records.append(DnsRecord(
                            record_type=record_type,
                            name=hostname,
                            value=val.rstrip("."),
                        ))
                elif "\t" in line or "  " in line:
                    # Generic record parsing
                    parts = line.split()
                    if len(parts) >= 2:
                        result.records.append(DnsRecord(
                            record_type=record_type,
                            name=hostname,
                            value=parts[-1].rstrip("."),
                        ))

    except subprocess.TimeoutExpired:
        result.resolution_time_ms = (time.monotonic() - start) * 1000
        result.error = "DNS resolution timed out (10s)"
    except Exception as e:
        result.resolution_time_ms = (time.monotonic() - start) * 1000
        result.error = str(e)

    return result


def resolve_system(hostname: str, record_type: str = "A") -> DnsResult:
    """Resolve using the system resolver for A/AAAA records, nslookup for others."""
    result = DnsResult(hostname=hostname, record_type=record_type, dns_server="system")

    if record_type in ("A", "AAAA"):
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        start = time.monotonic()
        try:
            addrs = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
            result.resolution_time_ms = (time.monotonic() - start) * 1000
            seen = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip not in seen:
                    seen.add(ip)
                    result.records.append(DnsRecord(
                        record_type=record_type,
                        name=hostname,
                        value=ip,
                    ))
        except socket.gaierror as e:
            result.resolution_time_ms = (time.monotonic() - start) * 1000
            result.error = f"DNS resolution failed: {e}"
        except Exception as e:
            result.resolution_time_ms = (time.monotonic() - start) * 1000
            result.error = str(e)
    else:
        return _resolve_with_nslookup(hostname, record_type)

    return result


def resolve_with_server(hostname: str, record_type: str, dns_server: str) -> DnsResult:
    """Resolve using a specific DNS server via nslookup."""
    return _resolve_with_nslookup(hostname, record_type, dns_server)


def check_propagation(hostname: str, record_type: str = "A") -> PropagationResult:
    """Check DNS propagation across multiple public DNS servers."""
    prop = PropagationResult(hostname=hostname, record_type=record_type)

    # System resolver
    prop.results["System"] = resolve_system(hostname, record_type)

    # Public DNS servers
    for name, server in DNS_SERVERS.items():
        prop.results[name] = resolve_with_server(hostname, record_type, server)

    return prop
