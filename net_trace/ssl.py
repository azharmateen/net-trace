"""SSL/TLS analyzer: certificate chain, expiry, cipher suite, protocol."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime


# Known weak ciphers
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED",
}

# Weak protocols
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class CertInfo:
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    serial_number: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    san: list[str] = field(default_factory=list)
    version: int = 0

    @property
    def days_until_expiry(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.utcnow()).days

    @property
    def is_expired(self) -> bool:
        if self.not_after is None:
            return False
        return self.not_after < datetime.utcnow()

    @property
    def expiry_urgency(self) -> str:
        days = self.days_until_expiry
        if days is None:
            return "unknown"
        if days < 0:
            return "expired"
        if days <= 7:
            return "critical"
        if days <= 30:
            return "warning"
        return "ok"

    def to_dict(self) -> dict:
        d = {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "version": self.version,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_until_expiry": self.days_until_expiry,
            "is_expired": self.is_expired,
            "expiry_urgency": self.expiry_urgency,
            "san": self.san,
        }
        return d


@dataclass
class SslResult:
    hostname: str
    port: int = 443
    protocol_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    certificate: CertInfo | None = None
    chain_length: int = 0
    sni_match: bool = True
    handshake_time_ms: float = 0.0
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        d = {
            "hostname": self.hostname,
            "port": self.port,
            "protocol_version": self.protocol_version,
            "cipher_suite": self.cipher_suite,
            "cipher_bits": self.cipher_bits,
            "chain_length": self.chain_length,
            "sni_match": self.sni_match,
            "handshake_time_ms": round(self.handshake_time_ms, 2),
            "warnings": self.warnings,
        }
        if self.certificate:
            d["certificate"] = self.certificate.to_dict()
        if self.error:
            d["error"] = self.error
        return d


def _parse_cert_name(name_tuples: tuple) -> dict:
    """Parse SSL certificate subject/issuer tuples into a dict."""
    result = {}
    for rdn in name_tuples:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_cert_date(date_str: str) -> datetime | None:
    """Parse SSL certificate date string."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def analyze_ssl(hostname: str, port: int = 443, timeout: float = 10.0) -> SslResult:
    """Perform SSL/TLS analysis on a host."""
    result = SslResult(hostname=hostname, port=port)

    ctx = ssl.create_default_context()

    start = time.monotonic()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result.handshake_time_ms = (time.monotonic() - start) * 1000

                # Protocol version
                result.protocol_version = ssock.version() or "unknown"

                # Cipher suite
                cipher = ssock.cipher()
                if cipher:
                    result.cipher_suite = cipher[0]
                    result.cipher_bits = cipher[2] if len(cipher) > 2 else 0

                # Certificate
                cert = ssock.getpeercert()
                if cert:
                    info = CertInfo()
                    info.subject = _parse_cert_name(cert.get("subject", ()))
                    info.issuer = _parse_cert_name(cert.get("issuer", ()))
                    info.serial_number = str(cert.get("serialNumber", ""))
                    info.version = cert.get("version", 0)

                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    if not_before:
                        info.not_before = _parse_cert_date(not_before)
                    if not_after:
                        info.not_after = _parse_cert_date(not_after)

                    # Subject Alternative Names
                    san = cert.get("subjectAltName", ())
                    info.san = [v for _, v in san]

                    result.certificate = info

                    # Check SNI
                    cn = info.subject.get("commonName", "")
                    all_names = [cn] + info.san
                    result.sni_match = any(
                        hostname == name or
                        (name.startswith("*.") and hostname.endswith(name[1:]))
                        for name in all_names
                    )

                # Chain length (from binary DER)
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    result.chain_length = 1  # At minimum the leaf cert

    except ssl.SSLCertVerificationError as e:
        result.handshake_time_ms = (time.monotonic() - start) * 1000
        result.error = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        result.handshake_time_ms = (time.monotonic() - start) * 1000
        result.error = f"SSL error: {e}"
    except socket.timeout:
        result.handshake_time_ms = (time.monotonic() - start) * 1000
        result.error = f"Connection timed out ({timeout}s)"
    except socket.gaierror as e:
        result.handshake_time_ms = (time.monotonic() - start) * 1000
        result.error = f"DNS resolution failed: {e}"
    except ConnectionRefusedError:
        result.handshake_time_ms = (time.monotonic() - start) * 1000
        result.error = f"Connection refused on port {port}"
    except Exception as e:
        result.handshake_time_ms = (time.monotonic() - start) * 1000
        result.error = str(e)

    # Check for weak ciphers
    if result.cipher_suite:
        for weak in WEAK_CIPHERS:
            if weak.upper() in result.cipher_suite.upper():
                result.warnings.append(f"Weak cipher component detected: {weak}")

    if result.cipher_bits and result.cipher_bits < 128:
        result.warnings.append(f"Cipher bit strength too low: {result.cipher_bits}")

    # Check protocol
    if result.protocol_version in WEAK_PROTOCOLS:
        result.warnings.append(f"Weak protocol: {result.protocol_version}")

    # Check SNI
    if not result.sni_match and not result.error:
        result.warnings.append("Hostname does not match certificate CN or SAN")

    # Check expiry
    if result.certificate:
        if result.certificate.is_expired:
            result.warnings.append("Certificate has EXPIRED")
        elif result.certificate.days_until_expiry is not None and result.certificate.days_until_expiry <= 30:
            result.warnings.append(
                f"Certificate expires in {result.certificate.days_until_expiry} days"
            )

    return result
