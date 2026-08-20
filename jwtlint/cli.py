"""jwtlint command-line entrypoint.

    jwtlint <token>                        decode + analyze a token
    jwtlint --file token.txt               read the token from a file
    jwtlint <token> --expect-alg RS256     flag RS-to-HS confusion risk
    jwtlint <token> --crack                try the built-in weak-secret wordlist
    jwtlint <token> --crack wordlist.txt   try a custom wordlist
"""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from jwtlint.checks import run_all
from jwtlint.parser import TokenParseError, parse
from jwtlint.wordlist import DEFAULT_WORDLIST

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

console = Console()


@click.command()
@click.argument("token", required=False)
@click.option("--file", "file_path", type=click.Path(exists=True, dir_okay=False), help="Read the token from a file instead of the argument.")
@click.option("--expect-alg", "expect_alg", help="Algorithm the server is expected to use (e.g. RS256). Flags RS-to-HS confusion risk if the token uses HS*.")
@click.option("--crack", "crack_target", is_flag=False, flag_value="__default__", default=None, help="Try to brute force the HMAC secret. Pass a wordlist path, or nothing to use the built-in list.")
@click.option("--max-lifetime-days", "max_lifetime_days", type=int, default=None, help="Flag tokens with exp - iat longer than this many days (default 365).")
@click.option("--json", "json_out", is_flag=True, help="Print findings as JSON instead of a table.")
@click.version_option(package_name="jwtlint")
def main(
    token: str | None,
    file_path: str | None,
    expect_alg: str | None,
    crack_target: str | None,
    max_lifetime_days: int | None,
    json_out: bool,
) -> None:
    """Static, offline JWT security analyzer. Parses TOKEN and reports findings."""
    token_text = _resolve_token(token, file_path)

    try:
        parsed = parse(token_text)
    except TokenParseError as exc:
        console.print(f"[bold red]error:[/] {exc}")
        sys.exit(2)

    wordlist = None
    if crack_target is not None:
        wordlist = DEFAULT_WORDLIST if crack_target == "__default__" else _load_wordlist(crack_target)

    max_lifetime_seconds = max_lifetime_days * 86400 if max_lifetime_days is not None else None

    findings = run_all(
        parsed,
        expect_alg=expect_alg,
        max_lifetime_seconds=max_lifetime_seconds,
        crack_wordlist=wordlist,
    )
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    if json_out:
        console.print_json(json.dumps({"header": parsed.header, "payload": parsed.payload, "findings": findings}))
    else:
        _print_decoded(parsed)
        _print_table(findings)

    if any(f["severity"] in ("critical", "high") for f in findings):
        sys.exit(1)


def _resolve_token(token: str | None, file_path: str | None) -> str:
    if file_path:
        with open(file_path) as fh:
            return fh.read().strip()
    if token:
        return token.strip()
    console.print("[bold red]error:[/] provide a token argument or --file")
    sys.exit(2)


def _load_wordlist(path: str) -> list[str]:
    try:
        with open(path) as fh:
            return [line.rstrip("\n") for line in fh]
    except OSError as exc:
        console.print(f"[bold red]error:[/] could not read wordlist {path!r}: {exc}")
        sys.exit(2)


def _print_decoded(parsed) -> None:
    header_json = json.dumps(parsed.header, indent=2, sort_keys=True)
    payload_json = json.dumps(parsed.payload, indent=2, sort_keys=True)
    console.print("[bold]header[/]")
    console.print(Syntax(header_json, "json", theme="ansi_dark", background_color="default"))
    console.print("[bold]payload[/]")
    console.print(Syntax(payload_json, "json", theme="ansi_dark", background_color="default"))


def _print_table(findings: list[dict]) -> None:
    table = Table(title="jwtlint findings", show_lines=False, header_style="bold")
    table.add_column("sev", width=8)
    table.add_column("check")
    table.add_column("finding")

    for f in findings:
        style = SEVERITY_STYLE.get(f["severity"], "")
        table.add_row(
            f"[{style}]{f['severity']}[/]",
            f["check"],
            f["title"],
        )

    console.print(table)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = "  ".join(f"[{SEVERITY_STYLE.get(sev, '')}]{sev}: {n}[/]" for sev, n in counts.items())
    console.print(f"\n{len(findings)} findings — {summary}\n")


if __name__ == "__main__":
    main()
