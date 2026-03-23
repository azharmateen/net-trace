"""Click CLI for net-trace."""

from __future__ import annotations

import json
from urllib.parse import urlparse

import click

from . import __version__
from .dns import check_propagation, resolve_system
from .headers import check_security_headers
from .http import trace_http
from .reporter import (
    print_dns_terminal,
    print_headers_terminal,
    print_http_terminal,
    print_propagation_terminal,
    print_ssl_terminal,
    to_json,
    to_markdown,
)
from .ssl import analyze_ssl


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """net-trace: Network debugging CLI.

    DNS resolution, SSL analysis, HTTP trace timing breakdown.
    """


@cli.command()
@click.argument("hostname")
@click.option("--type", "record_type", default="A",
              type=click.Choice(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"],
                                case_sensitive=False),
              help="DNS record type")
@click.option("--propagation/--no-propagation", default=False,
              help="Check propagation across public DNS servers")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]),
              default="terminal")
def dns(hostname: str, record_type: str, propagation: bool, fmt: str) -> None:
    """Resolve DNS records for a hostname.

    HOSTNAME is the domain name to resolve.
    """
    record_type = record_type.upper()

    if propagation:
        result = check_propagation(hostname, record_type)
        if fmt == "terminal":
            print_propagation_terminal(result)
        else:
            click.echo(to_json(result.to_dict()))
    else:
        result = resolve_system(hostname, record_type)
        if fmt == "terminal":
            print_dns_terminal(result)
        else:
            click.echo(to_json(result.to_dict()))


@cli.command()
@click.argument("hostname")
@click.option("--port", default=443, help="Port number")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]),
              default="terminal")
def ssl(hostname: str, port: int, fmt: str) -> None:
    """Analyze SSL/TLS certificate and connection.

    HOSTNAME is the domain to check.
    """
    result = analyze_ssl(hostname, port)
    if fmt == "terminal":
        print_ssl_terminal(result)
    else:
        click.echo(to_json(result.to_dict()))


@cli.command()
@click.argument("url")
@click.option("--follow-redirects/--no-follow-redirects", default=True,
              help="Follow HTTP redirects")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "markdown"]),
              default="terminal")
def http(url: str, follow_redirects: bool, fmt: str) -> None:
    """Trace HTTP request with timing breakdown.

    URL is the full URL to trace (must include scheme).
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = trace_http(url, follow_redirects=follow_redirects)
    if fmt == "terminal":
        print_http_terminal(result)
    elif fmt == "json":
        click.echo(to_json(result.to_dict()))
    else:
        click.echo(to_markdown(result.to_dict(), title=f"HTTP Trace: {url}"))


@cli.command()
@click.argument("url")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]),
              default="terminal")
def headers(url: str, fmt: str) -> None:
    """Check security headers for a URL.

    URL is the full URL to check.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # First, get the headers via HTTP trace
    http_result = trace_http(url, follow_redirects=True)
    if http_result.error:
        click.echo(f"Error: {http_result.error}", err=True)
        raise SystemExit(1)

    result = check_security_headers(url, http_result.headers)
    if fmt == "terminal":
        print_headers_terminal(result)
    else:
        click.echo(to_json(result.to_dict()))


@cli.command()
@click.argument("hostname")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]),
              default="terminal")
def full(hostname: str, fmt: str) -> None:
    """Run full analysis: DNS + SSL + HTTP + security headers.

    HOSTNAME is the domain to analyze.
    """
    from rich.console import Console
    console = Console()

    url = f"https://{hostname}"

    if fmt == "terminal":
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold]Full Network Trace: {hostname}[/bold]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

    all_data: dict = {"hostname": hostname}

    # DNS
    if fmt == "terminal":
        console.print("[bold]1. DNS Resolution[/bold]\n")
    dns_result = resolve_system(hostname)
    all_data["dns"] = dns_result.to_dict()
    if fmt == "terminal":
        print_dns_terminal(dns_result, console)
        console.print()

    # SSL
    if fmt == "terminal":
        console.print("[bold]2. SSL/TLS Analysis[/bold]\n")
    ssl_result = analyze_ssl(hostname)
    all_data["ssl"] = ssl_result.to_dict()
    if fmt == "terminal":
        print_ssl_terminal(ssl_result, console)
        console.print()

    # HTTP
    if fmt == "terminal":
        console.print("[bold]3. HTTP Trace[/bold]\n")
    http_result = trace_http(url)
    all_data["http"] = http_result.to_dict()
    if fmt == "terminal":
        print_http_terminal(http_result, console)
        console.print()

    # Security Headers
    if fmt == "terminal":
        console.print("[bold]4. Security Headers[/bold]\n")
    if not http_result.error:
        header_result = check_security_headers(url, http_result.headers)
        all_data["security_headers"] = header_result.to_dict()
        if fmt == "terminal":
            print_headers_terminal(header_result, console)
    else:
        if fmt == "terminal":
            console.print(f"[red]Skipped (HTTP error: {http_result.error})[/red]")
        all_data["security_headers"] = {"error": http_result.error}

    if fmt == "json":
        click.echo(to_json(all_data))


if __name__ == "__main__":
    cli()
