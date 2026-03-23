"""HTTP trace: timing breakdown, redirect chain, compression, caching."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class TimingBreakdown:
    dns_ms: float = 0.0
    connect_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    transfer_ms: float = 0.0
    total_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "dns_ms": round(self.dns_ms, 2),
            "connect_ms": round(self.connect_ms, 2),
            "tls_ms": round(self.tls_ms, 2),
            "ttfb_ms": round(self.ttfb_ms, 2),
            "transfer_ms": round(self.transfer_ms, 2),
            "total_ms": round(self.total_ms, 2),
        }


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "location": self.location,
        }


@dataclass
class HttpResult:
    url: str
    status_code: int = 0
    status_reason: str = ""
    timing: TimingBreakdown = field(default_factory=TimingBreakdown)
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    content_length: int = 0
    compression: str | None = None
    http_version: str = ""
    cache_control: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "status_code": self.status_code,
            "status_reason": self.status_reason,
            "http_version": self.http_version,
            "timing": self.timing.to_dict(),
            "content_length": self.content_length,
            "compression": self.compression,
            "cache_control": self.cache_control,
            "redirect_chain": [h.to_dict() for h in self.redirect_chain],
            "headers": self.headers,
        }
        if self.error:
            d["error"] = self.error
        return d


def _raw_http_request(
    host: str,
    port: int,
    path: str,
    use_tls: bool,
    timeout: float = 15.0,
) -> tuple[TimingBreakdown, int, str, dict[str, str], str, bytes]:
    """Make a raw HTTP/1.1 request and return timing + response parts."""
    timing = TimingBreakdown()
    overall_start = time.monotonic()

    # DNS resolution
    dns_start = time.monotonic()
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            raise socket.gaierror(f"No addresses found for {host}")
        family, socktype, proto, canonname, sockaddr = addr_info[0]
    except socket.gaierror as e:
        raise ConnectionError(f"DNS resolution failed: {e}")
    timing.dns_ms = (time.monotonic() - dns_start) * 1000

    # TCP connect
    connect_start = time.monotonic()
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    try:
        sock.connect(sockaddr)
    except Exception as e:
        sock.close()
        raise ConnectionError(f"TCP connect failed: {e}")
    timing.connect_ms = (time.monotonic() - connect_start) * 1000

    # TLS handshake
    if use_tls:
        tls_start = time.monotonic()
        ctx = ssl.create_default_context()
        try:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except Exception as e:
            sock.close()
            raise ConnectionError(f"TLS handshake failed: {e}")
        timing.tls_ms = (time.monotonic() - tls_start) * 1000

    # Send request
    request_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Accept: */*",
        "Accept-Encoding: gzip, deflate, br",
        "Connection: close",
        "User-Agent: net-trace/0.1.0",
        "",
        "",
    ]
    request = "\r\n".join(request_lines).encode("utf-8")

    send_start = time.monotonic()
    try:
        sock.sendall(request)
    except Exception as e:
        sock.close()
        raise ConnectionError(f"Send failed: {e}")

    # Receive response
    chunks = []
    first_byte = True
    try:
        while True:
            chunk = sock.recv(8192)
            if first_byte and chunk:
                timing.ttfb_ms = (time.monotonic() - send_start) * 1000
                first_byte = False
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    finally:
        sock.close()

    timing.transfer_ms = (time.monotonic() - send_start) * 1000 - timing.ttfb_ms
    timing.total_ms = (time.monotonic() - overall_start) * 1000

    raw = b"".join(chunks)

    # Parse response
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        header_end = raw.find(b"\n\n")
        if header_end == -1:
            header_end = len(raw)

    header_bytes = raw[:header_end]
    body = raw[header_end + 4:] if header_end < len(raw) else b""

    header_text = header_bytes.decode("utf-8", errors="replace")
    lines = header_text.split("\r\n") if "\r\n" in header_text else header_text.split("\n")

    status_code = 0
    status_reason = ""
    http_version = ""
    headers: dict[str, str] = {}

    if lines:
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        if len(parts) >= 2:
            http_version = parts[0]
            try:
                status_code = int(parts[1])
            except ValueError:
                pass
            if len(parts) >= 3:
                status_reason = parts[2]

        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

    return timing, status_code, status_reason, headers, http_version, body


def trace_http(
    url: str,
    follow_redirects: bool = True,
    max_redirects: int = 10,
    timeout: float = 15.0,
) -> HttpResult:
    """Trace an HTTP request with detailed timing breakdown."""
    result = HttpResult(url=url)
    current_url = url

    for _ in range(max_redirects + 1):
        parsed = urlparse(current_url)
        use_tls = parsed.scheme == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if use_tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            timing, status_code, status_reason, headers, http_version, body = _raw_http_request(
                host, port, path, use_tls, timeout
            )
        except ConnectionError as e:
            result.error = str(e)
            return result

        # Check for redirect
        if follow_redirects and status_code in (301, 302, 303, 307, 308):
            location = headers.get("location", "")
            if location:
                if location.startswith("/"):
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                result.redirect_chain.append(RedirectHop(
                    url=current_url,
                    status_code=status_code,
                    location=location,
                ))
                current_url = location
                continue

        # Final response
        result.url = current_url
        result.status_code = status_code
        result.status_reason = status_reason
        result.http_version = http_version
        result.headers = headers

        # Accumulate timing from redirects
        if result.redirect_chain:
            # Use the final request timing
            result.timing = timing
        else:
            result.timing = timing

        # Content info
        cl = headers.get("content-length")
        if cl:
            try:
                result.content_length = int(cl)
            except ValueError:
                result.content_length = len(body)
        else:
            result.content_length = len(body)

        result.compression = headers.get("content-encoding")
        result.cache_control = headers.get("cache-control")

        break

    return result
