"""Reports: colored terminal waterfall, JSON, markdown."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .dns import DnsResult, PropagationResult
from .headers import SecurityHeaderResult
from .http import HttpResult
from .ssl import SslResult


# ---------------------------------------------------------------------------
# DNS report
# ---------------------------------------------------------------------------

def print_dns_terminal(result: DnsResult, console: Console | None = None) -> None:
    console = console or Console()

    if result.error:
        console.print(f"[red]DNS Error: {result.error}[/red]")
        return

    title = f"DNS [{result.record_type}] {result.hostname} (via {result.dns_server})"
    table = Table(title=title, border_style="cyan")
    table.add_column("Type", style="bold")
    table.add_column("Value", style="green")
    table.add_column("TTL")

    for rec in result.records:
        table.add_row(rec.record_type, rec.value, str(rec.ttl) if rec.ttl else "-")

    console.print(table)
    console.print(f"[dim]Resolution time: {result.resolution_time_ms:.1f}ms[/dim]")


def print_propagation_terminal(result: PropagationResult, console: Console | None = None) -> None:
    console = console or Console()

    status = "[green]Consistent[/green]" if result.is_consistent else "[red]Inconsistent[/red]"
    console.print(Panel(f"DNS Propagation: {result.hostname} [{result.record_type}] - {status}",
                        border_style="cyan"))

    table = Table(border_style="cyan")
    table.add_column("Server", style="bold")
    table.add_column("Records", style="green")
    table.add_column("Time (ms)")

    for name, dns_result in result.results.items():
        if dns_result.error:
            table.add_row(name, f"[red]Error: {dns_result.error}[/red]", "-")
        else:
            values = ", ".join(r.value for r in dns_result.records) or "(none)"
            table.add_row(name, values, f"{dns_result.resolution_time_ms:.1f}")

    console.print(table)


# ---------------------------------------------------------------------------
# SSL report
# ---------------------------------------------------------------------------

def print_ssl_terminal(result: SslResult, console: Console | None = None) -> None:
    console = console or Console()

    if result.error:
        console.print(f"[red]SSL Error: {result.error}[/red]")
        return

    console.print(Panel(f"SSL/TLS Analysis: {result.hostname}:{result.port}",
                        border_style="cyan"))

    table = Table(border_style="cyan", show_header=False)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Protocol", result.protocol_version)
    table.add_row("Cipher Suite", result.cipher_suite)
    table.add_row("Cipher Bits", str(result.cipher_bits))
    table.add_row("Handshake Time", f"{result.handshake_time_ms:.1f}ms")
    table.add_row("SNI Match", "[green]Yes[/green]" if result.sni_match else "[red]No[/red]")

    if result.certificate:
        cert = result.certificate
        cn = cert.subject.get("commonName", "N/A")
        issuer_cn = cert.issuer.get("commonName", "N/A")
        table.add_row("Subject CN", cn)
        table.add_row("Issuer", issuer_cn)
        table.add_row("Not Before", cert.not_before.isoformat() if cert.not_before else "N/A")
        table.add_row("Not After", cert.not_after.isoformat() if cert.not_after else "N/A")

        urgency_styles = {"ok": "green", "warning": "yellow", "critical": "red", "expired": "bold red"}
        style = urgency_styles.get(cert.expiry_urgency, "dim")
        days = cert.days_until_expiry
        expiry_text = f"{days} days ({cert.expiry_urgency})" if days is not None else "N/A"
        table.add_row("Days Until Expiry", Text(expiry_text, style=style))

        if cert.san:
            table.add_row("SANs", ", ".join(cert.san[:5]) + ("..." if len(cert.san) > 5 else ""))

    console.print(table)

    if result.warnings:
        for w in result.warnings:
            console.print(f"  [yellow]Warning: {w}[/yellow]")


# ---------------------------------------------------------------------------
# HTTP report
# ---------------------------------------------------------------------------

def _render_waterfall_bar(label: str, ms: float, max_ms: float, width: int = 40) -> str:
    """Render a single bar in the timing waterfall."""
    if max_ms <= 0:
        return f"  {label:>12}: {ms:.1f}ms"
    bar_len = int((ms / max_ms) * width) if ms > 0 else 0
    bar_len = max(bar_len, 1) if ms > 0 else 0
    bar = "\u2588" * bar_len
    return f"  {label:>12}: {bar} {ms:.1f}ms"


def print_http_terminal(result: HttpResult, console: Console | None = None) -> None:
    console = console or Console()

    if result.error:
        console.print(f"[red]HTTP Error: {result.error}[/red]")
        return

    status_style = "green" if 200 <= result.status_code < 300 else (
        "yellow" if 300 <= result.status_code < 400 else "red"
    )

    console.print(Panel(
        f"HTTP Trace: {result.url}",
        border_style="cyan",
    ))

    console.print(f"  Status: [{status_style}]{result.status_code} {result.status_reason}[/{status_style}]")
    console.print(f"  HTTP Version: {result.http_version}")

    if result.redirect_chain:
        console.print(f"\n  [yellow]Redirect chain ({len(result.redirect_chain)} hops):[/yellow]")
        for hop in result.redirect_chain:
            console.print(f"    {hop.status_code} {hop.url} -> {hop.location}")

    # Timing waterfall
    t = result.timing
    max_ms = max(t.dns_ms, t.connect_ms, t.tls_ms, t.ttfb_ms, t.transfer_ms, 1)

    console.print(f"\n  [bold]Timing Waterfall:[/bold]")
    console.print(f"  [cyan]{_render_waterfall_bar('DNS', t.dns_ms, max_ms)}[/cyan]")
    console.print(f"  [blue]{_render_waterfall_bar('TCP Connect', t.connect_ms, max_ms)}[/blue]")
    console.print(f"  [magenta]{_render_waterfall_bar('TLS', t.tls_ms, max_ms)}[/magenta]")
    console.print(f"  [yellow]{_render_waterfall_bar('TTFB', t.ttfb_ms, max_ms)}[/yellow]")
    console.print(f"  [green]{_render_waterfall_bar('Transfer', t.transfer_ms, max_ms)}[/green]")
    console.print(f"  {'─' * 60}")
    console.print(f"  [bold]{'Total':>12}: {t.total_ms:.1f}ms[/bold]")

    # Additional info
    info_parts = []
    if result.compression:
        info_parts.append(f"Compression: {result.compression}")
    if result.cache_control:
        info_parts.append(f"Cache: {result.cache_control}")
    info_parts.append(f"Content-Length: {result.content_length}")
    if info_parts:
        console.print(f"\n  {' | '.join(info_parts)}")


# ---------------------------------------------------------------------------
# Security headers report
# ---------------------------------------------------------------------------

def print_headers_terminal(result: SecurityHeaderResult, console: Console | None = None) -> None:
    console = console or Console()

    grade_styles = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    grade_style = grade_styles.get(result.grade, "dim")

    console.print(Panel(
        Text.assemble(
            ("Security Headers: ", "bold"),
            (result.url, "cyan"),
            (" - Grade: ", ""),
            (result.grade, grade_style),
            (f" ({result.score}/{result.max_score})", "dim"),
        ),
        border_style="cyan",
    ))

    table = Table(border_style="cyan")
    table.add_column("Header", style="bold")
    table.add_column("Present")
    table.add_column("Value")
    table.add_column("Notes")

    for check in result.checks:
        present_text = Text("Yes", style="green") if check.present else Text("No", style="red")
        table.add_row(
            check.name,
            present_text,
            (check.value or "-")[:50],
            check.notes[:60],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# JSON / Markdown
# ---------------------------------------------------------------------------

def to_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


def to_markdown(data: dict, title: str = "Network Trace") -> str:
    lines = [f"# {title}", ""]

    def _render_dict(d: dict, depth: int = 0) -> None:
        indent = "  " * depth
        for key, val in d.items():
            if isinstance(val, dict):
                lines.append(f"{indent}- **{key}**:")
                _render_dict(val, depth + 1)
            elif isinstance(val, list):
                lines.append(f"{indent}- **{key}**:")
                for item in val:
                    if isinstance(item, dict):
                        _render_dict(item, depth + 1)
                    else:
                        lines.append(f"{indent}  - {item}")
            else:
                lines.append(f"{indent}- **{key}**: {val}")

    _render_dict(data)
    return "\n".join(lines)
