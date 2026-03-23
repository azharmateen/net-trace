"""Security header checker: analyze and score HTTP security headers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: str | None = None
    expected: str | None = None
    weight: int = 10
    notes: str = ""

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "present": self.present,
            "weight": self.weight,
        }
        if self.value is not None:
            d["value"] = self.value
        if self.expected is not None:
            d["expected"] = self.expected
        if self.notes:
            d["notes"] = self.notes
        return d


@dataclass
class SecurityHeaderResult:
    url: str
    grade: str = "F"
    score: int = 0
    max_score: int = 100
    checks: list[HeaderCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "grade": self.grade,
            "score": self.score,
            "max_score": self.max_score,
            "checks": [c.to_dict() for c in self.checks],
        }


# Security headers to check with their weight
HEADER_SPECS = [
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "weight": 20,
        "expected": "max-age=31536000; includeSubDomains",
        "validate": lambda v: "max-age=" in v.lower() if v else False,
        "notes_missing": "HSTS not set. Clients can be MitM'd on first visit.",
        "notes_weak": "HSTS max-age should be at least 31536000 (1 year).",
    },
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "weight": 20,
        "expected": "default-src 'self'",
        "validate": lambda v: "default-src" in v.lower() or "script-src" in v.lower() if v else False,
        "notes_missing": "No CSP header. XSS protection via CSP is critical.",
        "notes_weak": "CSP is set but may be too permissive.",
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "weight": 15,
        "expected": "DENY or SAMEORIGIN",
        "validate": lambda v: v.upper() in ("DENY", "SAMEORIGIN") if v else False,
        "notes_missing": "No X-Frame-Options. Site may be vulnerable to clickjacking.",
        "notes_weak": "X-Frame-Options value should be DENY or SAMEORIGIN.",
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "weight": 10,
        "expected": "nosniff",
        "validate": lambda v: v.lower().strip() == "nosniff" if v else False,
        "notes_missing": "No X-Content-Type-Options. MIME type sniffing possible.",
        "notes_weak": "Value should be 'nosniff'.",
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "weight": 10,
        "expected": "strict-origin-when-cross-origin",
        "validate": lambda v: v.lower().strip() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin"
        ) if v else False,
        "notes_missing": "No Referrer-Policy. Referrer leaks may occur.",
        "notes_weak": "Consider stricter Referrer-Policy.",
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "weight": 10,
        "expected": "geolocation=(), camera=(), microphone=()",
        "validate": lambda v: len(v) > 0 if v else False,
        "notes_missing": "No Permissions-Policy. Browser features unrestricted.",
        "notes_weak": "",
    },
    {
        "name": "X-XSS-Protection",
        "key": "x-xss-protection",
        "weight": 5,
        "expected": "0 (modern approach) or 1; mode=block",
        "validate": lambda v: v.strip() in ("0", "1; mode=block", "1;mode=block") if v else False,
        "notes_missing": "No X-XSS-Protection. Less important with CSP but still recommended.",
        "notes_weak": "Use '0' (rely on CSP) or '1; mode=block'.",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "weight": 5,
        "expected": "same-origin",
        "validate": lambda v: v.lower().strip() in ("same-origin", "same-origin-allow-popups") if v else False,
        "notes_missing": "No COOP header.",
        "notes_weak": "",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "key": "cross-origin-resource-policy",
        "weight": 5,
        "expected": "same-origin",
        "validate": lambda v: v.lower().strip() in ("same-origin", "same-site", "cross-origin") if v else False,
        "notes_missing": "No CORP header.",
        "notes_weak": "",
    },
]


def _score_to_grade(score: int, max_score: int) -> str:
    """Convert numeric score to letter grade."""
    pct = (score / max_score) * 100 if max_score > 0 else 0
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"


def check_security_headers(url: str, headers: dict[str, str]) -> SecurityHeaderResult:
    """Analyze security headers and return scored result."""
    result = SecurityHeaderResult(url=url)
    total_weight = 0
    earned = 0

    for spec in HEADER_SPECS:
        weight = spec["weight"]
        total_weight += weight
        key = spec["key"]
        value = headers.get(key)

        check = HeaderCheck(
            name=spec["name"],
            present=value is not None,
            value=value,
            expected=spec["expected"],
            weight=weight,
        )

        if value is not None:
            validate = spec["validate"]
            if validate(value):
                earned += weight
                check.notes = "OK"
            else:
                earned += weight // 2  # Partial credit for being present but weak
                check.notes = spec.get("notes_weak", "Value may not be optimal")
        else:
            check.notes = spec.get("notes_missing", "Header not present")

        result.checks.append(check)

    # Bonus: check for dangerous headers that should be absent
    dangerous = {
        "server": "Server header reveals software version",
        "x-powered-by": "X-Powered-By reveals technology stack",
        "x-aspnet-version": "X-AspNet-Version reveals framework version",
    }
    for key, note in dangerous.items():
        if key in headers:
            check = HeaderCheck(
                name=f"Remove: {key}",
                present=True,
                value=headers[key],
                weight=0,
                notes=note,
            )
            result.checks.append(check)
            earned = max(0, earned - 5)

    result.max_score = total_weight
    result.score = earned
    result.grade = _score_to_grade(earned, total_weight)

    return result
