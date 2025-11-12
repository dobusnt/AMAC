from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from ._json import dumps, loads
from .config import (
    assert_urls_in_scope,
    load_auth_config,
    load_scope_config,
)
from .diffing import analyze_run_dir
from .discovery.openapi import load_and_map_openapi
from .models import EndpointSet
from .report import render_report
from .runner import run_basic_probes

app = typer.Typer(add_completion=False, help="AMAC — API Mapper + Auth Checker")
console = Console()


# -----------------------------
# Global callback / banner / --version
# -----------------------------

@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show AMAC version and exit.",
        is_eager=True,
    ),
):
    if version:
        console.print(f"AMAC {__version__}")
        raise typer.Exit()

    # Friendly safety banner (printed on entry)
    console.print("[yellow]WARNING:[/yellow] Authorized targets only. Respect program scope, rate limits, and ToS.")

    # If no subcommand provided, show help and exit (instead of 'Missing command')
    if ctx.invoked_subcommand is None:
        console.print()
        console.print(app.get_help(ctx))
        raise typer.Exit()


@app.command(help="Show AMAC version.")
def version() -> None:  # allows `amac version` as well
    console.print(f"AMAC {__version__}")


# -----------------------------
# Helpers
# -----------------------------

def _write_json(obj, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = obj.model_dump() if hasattr(obj, "model_dump") else obj
    out_path.write_bytes(dumps(payload))


def _read_json(path: Path) -> dict:
    return loads(path.read_bytes())


def _show_endpoints_table(es: EndpointSet, limit: int = 12) -> None:
    table = Table(title=f"Endpoints ({len(es.endpoints)} total; showing up to {limit})")
    table.add_column("#", style="bold", justify="right")
    table.add_column("Method")
    table.add_column("URL")
    table.add_column("Auth Declared?")
    table.add_column("Tags")

    for i, ep in enumerate(es.endpoints[:limit], start=1):
        req_auth = "yes" if ep.requires_auth is True else "no" if ep.requires_auth is False else "unknown"
        tags = ", ".join(ep.tags) if ep.tags else "-"
        table.add_row(str(i), ep.method, ep.url, req_auth, tags)

    console.print(table)


def _show_probe_preview(summary_json: dict, limit: int = 12) -> None:
    rows = summary_json.get("rows", [])
    table = Table(title=f"Probe Summary ({len(rows)} endpoints; showing up to {limit})")
    table.add_column("#", style="bold", justify="right")
    table.add_column("Method")
    table.add_column("URL")
    table.add_column("Req. Auth?")
    table.add_column("No-Auth")
    table.add_column("Auth (first)")
    table.add_column("Δ Size")

    def _req_auth(v):
        return "yes" if v is True else "no" if v is False else "unknown"

    for r in rows[:limit]:
        no_s = r.get("noauth_status")
        au_s = r.get("auth_status")
        no_sz = r.get("noauth_size") or 0
        au_sz = r.get("auth_size") or 0
        dsz = au_sz - no_sz if (au_s is not None and no_s is not None) else 0

        table.add_row(
            str(r.get("index")),
            r.get("method", "-"),
            r.get("url", "-"),
            _req_auth(r.get("requires_auth")),
            "-" if no_s is None else str(no_s),
            "-" if au_s is None else f"{r.get('auth_name','auth')}:{au_s}",
            str(dsz),
        )

    console.print(table)


def _show_matrix_preview(summary_json: dict, limit: int = 10) -> None:
    """
    RBAC matrix preview: per-identity statuses for first few endpoints.
    """
    matrix = summary_json.get("matrix", [])
    idents: List[str] = list(summary_json.get("auth_used") or [])
    if not matrix or not idents:
        return

    # Cap identities to avoid overly wide table in console
    max_id_cols = 4
    idents_shown = idents[:max_id_cols]
    hidden = len(idents) - len(idents_shown)

    title = "RBAC Matrix (first identities shown"
    title += f"; +{hidden} more)" if hidden > 0 else ")"

    t = Table(title=title)
    t.add_column("#", justify="right", style="bold")
    t.add_column("Method", width=7)
    t.add_column("URL")

    for name in idents_shown:
        t.add_column(name, justify="center")

    def _cell(status):
        return "-" if status is None else str(status)

    for row in matrix[:limit]:
        vals = [str(row.get("index")), row.get("method", ""), row.get("url", "")]
        for name in idents_shown:
            v = row.get("variants", {}).get(name) or {}
            vals.append(_cell(v.get("status")))
        t.add_row(*vals)

    console.print(t)


def _show_findings_preview(findings_json: dict, limit: int = 10) -> None:
    counts = findings_json.get("counts", {})
    table_top = Table(title="Findings — Summary")
    table_top.add_column("Total Endpoints", justify="right")
    table_top.add_column("Total Findings", justify="right")
    table_top.add_column("By Severity")
    table_top.add_column("By Type (top)")
    sev = counts.get("by_severity", {})
    typ = counts.get("by_type", {})
    by_sev = ", ".join(f"{k}:{v}" for k, v in sorted(sev.items()))
    top_types = ", ".join(f"{k}:{v}" for k, v in sorted(typ.items(), key=lambda kv: -kv[1])[:5])
    table_top.add_row(
        str(counts.get("total_endpoints", 0)),
        str(counts.get("total_findings", 0)),
        by_sev or "-",
        top_types or "-",
    )
    console.print(table_top)

    items = findings_json.get("findings", [])[:limit]
    if not items:
        console.print("[green]No findings under current heuristics.[/green]")
        return

    table = Table(title=f"Findings — First {len(items)}")
    table.add_column("#", justify="right")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Method")
    table.add_column("URL")
    table.add_column("no->auth")
    table.add_column("Δsize")
    for i, f in enumerate(items, 1):
        table.add_row(
            str(i),
            f.get("severity", "").upper(),
            f.get("type", ""),
            f.get("method", ""),
            f.get("url", ""),
            f"{f.get('noauth_status')}->{f.get('auth_status')}",
            str(f.get("delta_size")),
        )
    console.print(table)


# -----------------------------
# Commands
# -----------------------------

@app.command(help="Map GET/HEAD endpoints from an OpenAPI/Swagger file or URL.")
def map(
    openapi: str = typer.Option(
        ...,
        "--openapi",
        help="Path or URL to OpenAPI/Swagger (JSON or YAML).",
    ),
    scope: Path = typer.Option(
        ...,
        "--scope",
        help="Path to scope.yml (allowed/denied/base_urls, rate limits).",
    ),
    out: Path = typer.Option(
        Path("endpoints.json"),
        "--out",
        help="Where to write the resulting endpoints.json.",
    ),
    no_preview: bool = typer.Option(
        False,
        "--no-preview",
        help="Do not print a table preview of mapped endpoints.",
    ),
):
    """
    Loads scope.yml, fetches/parses the OpenAPI spec, builds an EndpointSet (GET/HEAD),
    enforces scope, and writes endpoints.json.
    """
    if not scope.exists():
        console.print(f"[red]Error: scope file not found: {scope}[/red]")
        raise typer.Exit(code=2)
    try:
        scope_cfg = load_scope_config(scope)
    except Exception as e:
        console.print(f"[red]Error loading scope config:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        endpoint_set = asyncio.run(load_and_map_openapi(openapi, scope_cfg))
    except Exception as e:
        console.print(f"[red]Failed to map OpenAPI:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        _write_json(endpoint_set, out)
    except Exception as e:
        console.print(f"[red]Failed to write {out}:[/red] {e}")
        raise typer.Exit(code=2)

    console.print(
        f"[green]Wrote {len(endpoint_set.endpoints)} endpoints ->[/green] {out.resolve()}"
    )
    if not no_preview:
        _show_endpoints_table(endpoint_set)


@app.command(help="Validate configs and an endpoints.json file.")
def check(
    endpoints: Path = typer.Option(
        ...,
        "--endpoints",
        help="Path to endpoints.json produced by `amac map`.",
    ),
    scope: Path = typer.Option(
        ...,
        "--scope",
        exists=True,
        readable=True,
        help="Path to scope.yml (used to re-assert in-scope URLs).",
    ),
    auth: Path = typer.Option(
        ...,
        "--auth",
        help="Path to auth.yml (validate auth schemes for later probes).",
    ),
    no_preview: bool = typer.Option(
        False,
        "--no-preview",
        help="Do not show a table preview of endpoints.",
    ),
):
    """
    Validates:
      - scope.yml structure
      - auth.yml structure (at least one scheme, required fields present)
      - endpoints.json structure, and that all URLs are within scope
    """
    if not scope.exists() or not scope.is_file():
        console.print(f"[red]Error: scope file not found: {scope}[/red]")
        raise typer.Exit(code=2)
    if not auth.exists() or not auth.is_file():
        console.print(f"[red]Error: auth file not found: {auth}[/red]")
        raise typer.Exit(code=2)
    if not endpoints.exists() or not endpoints.is_file():
        console.print(f"[red]Error: endpoints file not found: {endpoints}[/red]")
        raise typer.Exit(code=2)
    try:
        scope_cfg = load_scope_config(scope)
    except Exception as e:
        console.print(f"[red]Invalid scope.yml:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        auth_cfg = load_auth_config(auth)
    except Exception as e:
        console.print(f"[red]Invalid auth.yml:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        raw = _read_json(endpoints)
        es = EndpointSet.model_validate(raw)
    except Exception as e:
        console.print(f"[red]Invalid endpoints.json:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        assert_urls_in_scope([e.url for e in es.endpoints], scope_cfg)
    except Exception as e:
        console.print(f"[red]Scope violation:[/red] {e}")
        raise typer.Exit(code=2)

    n = len(es.endpoints)
    identities = ", ".join([s.name for s in auth_cfg.auth_schemes]) or "-"
    console.print("[green]Configs validated successfully.[/green]")
    console.print(f"[bold]Endpoints:[/bold] {n}")
    console.print(f"[bold]Auth schemes:[/bold] {identities}")

    if not no_preview and n:
        _show_endpoints_table(es)


@app.command(help="Run probes (no-auth plus identities) for endpoints.json.")
def probe(
    endpoints: Path = typer.Option(
        ...,
        "--endpoints",
        help="Path to endpoints.json produced by `amac map`.",
    ),
    scope: Path = typer.Option(
        ...,
        "--scope",
        exists=True,
        readable=True,
        help="Path to scope.yml (rate limits, timeouts, scope/path gates).",
    ),
    auth: Path = typer.Option(
        ...,
        "--auth",
        exists=True,
        readable=True,
        help="Path to auth.yml (can include multiple identities).",
    ),
    identities: str = typer.Option(
        "all",
        "--identities",
        help="Which identities to use from auth.yml: 'first' or 'all'.",
        case_sensitive=False,
    ),
    out_dir: Optional[Path] = typer.Option(
        None,
        "--out-dir",
        help="Directory to write snapshots and summary.json (default: out/run_YYYY-MM-DD_HH-MM-SS).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Plan requests only; don't send network traffic.",
    ),
    no_preview: bool = typer.Option(
        False,
        "--no-preview",
        help="Do not show a table preview of probe results.",
    ),
):
    """
    Loads configs and endpoints, then executes:
      - No-auth request
      - One or ALL identities from auth.yml (RBAC matrix)

    Writes per-request snapshots under OUT/requests and a summary at OUT/summary.json.
    """
    if out_dir is None:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        out_dir = Path("out") / f"run_{ts}"

    use_all = (identities or "all").lower() != "first"

    if not scope.exists() or not scope.is_file():
        console.print(f"[red]Error: scope file not found: {scope}[/red]")
        raise typer.Exit(code=2)
    if not auth.exists() or not auth.is_file():
        console.print(f"[red]Error: auth file not found: {auth}[/red]")
        raise typer.Exit(code=2)
    if not endpoints.exists() or not endpoints.is_file():
        console.print(f"[red]Error: endpoints file not found: {endpoints}[/red]")
        raise typer.Exit(code=2)
    try:
        scope_cfg = load_scope_config(scope)
    except Exception as e:
        console.print(f"[red]Invalid scope.yml:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        auth_cfg = load_auth_config(auth)
    except Exception as e:
        console.print(f"[red]Invalid auth.yml:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        raw = _read_json(endpoints)
        es = EndpointSet.model_validate(raw)
    except Exception as e:
        console.print(f"[red]Invalid endpoints.json:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        assert_urls_in_scope([e.url for e in es.endpoints], scope_cfg)
    except Exception as e:
        console.print(f"[red]Scope violation:[/red] {e}")
        raise typer.Exit(code=2)

    try:
        meta = asyncio.run(
            run_basic_probes(
                es,
                scope_cfg,
                auth_cfg,
                out_dir,
                dry_run=dry_run,
                use_all_identities=use_all,
            )
        )
    except Exception as e:
        console.print(f"[red]Probe run failed:[/red] {e}")
        raise typer.Exit(code=2)

    console.print(
        f"[green]{'Dry-run planned' if dry_run else 'Probes complete'}.[/green] Summary -> {meta['summary']}\nRequests -> {meta['requests_dir']}"
    )

    if not no_preview:
        try:
            summary_json = _read_json(Path(meta["summary"]))
            if dry_run:
                console.print(f"[cyan]Planned requests:[/cyan] {summary_json.get('planned_requests', 'n/a')}")
            else:
                _show_probe_preview(summary_json)
                _show_matrix_preview(summary_json)
        except Exception:
            pass


@app.command(help="Analyze a probe run directory -> findings.json + findings.md.")
def analyze(
    run_dir: Path = typer.Option(
        ...,
        "--run-dir",
        help="Directory created by `amac probe` (contains summary.json).",
    ),
    no_preview: bool = typer.Option(
        False,
        "--no-preview",
        help="Do not show a summary of findings.",
    ),
):
    if not run_dir.exists() or not run_dir.is_dir():
        console.print(f"[red]Error: run directory not found: {run_dir}[/red]")
        raise typer.Exit(code=2)
    try:
        findings_json_path, findings_md_path = analyze_run_dir(run_dir)
    except Exception as e:
        console.print(f"[red]Analyze failed:[/red] {e}")
        raise typer.Exit(code=2)

    console.print(
        f"[green]Wrote findings.[/green]\nJSON -> {findings_json_path}\nMarkdown -> {findings_md_path}"
    )

    if not no_preview:
        try:
            findings_json = _read_json(Path(findings_json_path))
            _show_findings_preview(findings_json)
        except Exception:
            pass


@app.command(help="Render a standalone HTML report from a probe run directory.")
def report(
    run_dir: Path = typer.Option(
        ...,
        "--run-dir",
        help="Directory created by `amac probe` (contains summary.json).",
    ),
    out_html: Optional[Path] = typer.Option(
        None,
        "--out-html",
        help="Path to write HTML report (default: {run_dir}/report.html).",
    ),
):
    if not run_dir.exists() or not run_dir.is_dir():
        console.print(f"[red]Error: run directory not found: {run_dir}[/red]")
        raise typer.Exit(code=2)
    try:
        html_path = render_report(run_dir, out_html)
    except Exception as e:
        console.print(f"[red]Report generation failed:[/red] {e}")
        raise typer.Exit(code=2)

    console.print(f"[green]Report written ->[/green] {html_path.resolve()}")


if __name__ == "__main__":
    app()
