from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from .._json import dumps
from ..auth.flows import fetch_oauth2_token, perform_form_login, refresh_oauth2_token
from ..config import assert_urls_in_scope

# 🔧 import from package init to avoid module-attribute lookup issues
from ..evidence import write_snapshot
from ..models import (
    AuthConfig,
    AuthScheme,
    Endpoint,
    EndpointSet,
    RequestPolicy,
    ScopeConfig,
    Timeouts,
)
from .client import HttpClient

console = Console()


# -----------------------------
# Public API
# -----------------------------

@dataclass
class ProbeSummaryRow:
    index: int
    method: str
    url: str
    requires_auth: Optional[bool]
    noauth_status: Optional[int]
    auth_name: Optional[str]
    auth_status: Optional[int]
    noauth_size: Optional[int]
    auth_size: Optional[int]
    notes: Optional[str] = None


@dataclass
class VariantResult:
    status: Optional[int]
    size: Optional[int]
    error: Optional[str] = None  # error message if request errored


async def run_basic_probes(
    endpoints: EndpointSet,
    scope: ScopeConfig,
    auth: AuthConfig,
    out_dir: Path,
    *,
    dry_run: bool = False,
    use_all_identities: bool = True,
) -> Dict[str, Any]:
    """
    Run probes per endpoint:
      - No-auth
      - One or ALL auth schemes (RBAC matrix)
    Writes per-request snapshots under out_dir/requests and a summary JSON at out_dir/summary.json.
    Returns a metadata dict.

    If dry_run=True, no requests are sent; we only compute planned counts and write a tiny summary.
    """
    # Scope/sanity
    assert_urls_in_scope([e.url for e in endpoints.endpoints], scope)

    # IO setup
    out_dir.mkdir(parents=True, exist_ok=True)
    req_dir = out_dir / "requests"
    req_dir.mkdir(parents=True, exist_ok=True)

    # Choose identities
    auth_schemes: List[AuthScheme] = list(auth.auth_schemes or [])
    if not auth_schemes:
        # We still run no-auth only
        auth_schemes = []

    if not use_all_identities and auth_schemes:
        auth_schemes = [auth_schemes[0]]

    planned_requests = len(endpoints.endpoints) * (1 + max(1, len(auth_schemes)) if auth_schemes else 1)

    if dry_run:
        summary_path = out_dir / "summary.json"
        _write_json(
            {
                "version": "0.2.0",
                "endpoints": len(endpoints.endpoints),
                "auth_used": [s.name for s in auth_schemes],
                "planned_requests": planned_requests,
                "rows": [],
                "matrix": [],
                "dry_run": True,
            },
            summary_path,
        )
        return {
            "summary": str(summary_path),
            "requests_dir": str(req_dir),
            "endpoints": len(endpoints.endpoints),
            "auth_used": [s.name for s in auth_schemes],
            "planned_requests": planned_requests,
            "dry_run": True,
        }

    # Client configuration
    rp: RequestPolicy = scope.request_policy
    to: Timeouts = scope.timeouts

    async with HttpClient(
        timeouts=to,
        max_rps=rp.max_rps,
        concurrency=rp.concurrency,
        per_host_concurrency=rp.per_host_concurrency,
        user_agent="AMAC/0.2.0",
        max_attempts=3,
        backoff_base=0.6,
        backoff_cap_s=rp.backoff_cap_s,
        allow_redirects=rp.allow_redirects,
        verify_tls=rp.verify_tls,
        global_jitter_ms=rp.global_jitter_ms,
        hard_request_budget=rp.hard_request_budget,
        privacy_level=scope.evidence.privacy_level,  # privacy: none|minimal|strict
    ) as client:
        # Resolve dynamic auth (oauth2/form_login → bearer/cookie)
        effective_identities: List[AuthScheme] = []
        for s in auth_schemes:
            eff = await _resolve_identity(s)
            effective_identities.append(eff)

        # Build tasks
        legacy_rows: List[ProbeSummaryRow] = []
        matrix_rows: List[Dict[str, Any]] = []

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            transient=True,
            console=console,
        )

        BATCH = max(1, rp.concurrency * 6)
        total = len(endpoints.endpoints)
        completed = 0

        with progress:
            task_id = progress.add_task("Probing endpoints", total=total)

            for batch_start in range(0, total, BATCH):
                batch_eps = endpoints.endpoints[batch_start : batch_start + BATCH]
                tasks = [
                    asyncio.create_task(
                        _probe_one(
                            client,
                            idx=(i + batch_start),
                            ep=ep,
                            identities=effective_identities,
                            req_dir=req_dir,
                        )
                    )
                    for i, ep in enumerate(batch_eps)
                ]

                for coro in asyncio.as_completed(tasks):
                    legacy_row, matrix_row = await coro
                    legacy_rows.append(legacy_row)
                    matrix_rows.append(matrix_row)
                    completed += 1
                    progress.update(task_id, completed=completed)

        # Sort rows by index for determinism
        legacy_rows.sort(key=lambda r: r.index)
        matrix_rows.sort(key=lambda r: r["index"])

    # Write summary
    summary_path = out_dir / "summary.json"
    _write_json(
        {
            "version": "0.2.0",
            "endpoints": len(endpoints.endpoints),
            "auth_used": [s.name for s in effective_identities],
            "rows": [row.__dict__ for row in legacy_rows],  # backward compatible (uses first identity)
            "matrix": matrix_rows,  # RBAC matrix view (all identities)
            "dry_run": False,
        },
        summary_path,
    )

    return {
        "summary": str(summary_path),
        "requests_dir": str(req_dir),
        "endpoints": len(endpoints.endpoints),
        "auth_used": [s.name for s in effective_identities],
        "dry_run": False,
    }


# -----------------------------
# Internals
# -----------------------------

def _safe_stem(s: str, limit: int = 80) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch in ("-", "_"):
            out.append(ch)
        else:
            out.append("_")
        if len(out) >= limit:
            break
    return "".join(out).strip("_") or "item"


def _write_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "model_dump"):
        payload = obj.model_dump()
    elif isinstance(obj, dict):
        payload = obj
    else:
        try:
            payload = obj.__dict__  # dataclasses etc.
        except Exception:
            payload = obj
    path.write_bytes(dumps(payload))


async def _resolve_identity(s: AuthScheme) -> AuthScheme:
    """
    Turn dynamic schemes into effective ones consumable by HttpClient:
      - oauth2 → bearer
      - form_login → cookie
      - others → passthrough
    """
    if s.type == "oauth2":
        token = await fetch_oauth2_token(s)
        return AuthScheme(
            name=s.name, type="bearer", token=token, header="Authorization"
        )
    if s.type == "form_login":
        cookie = await perform_form_login(s)
        return AuthScheme(name=s.name, type="cookie", cookie=cookie)
    return s


async def _authed_request_with_refresh(
    client: HttpClient,
    method: str,
    url: str,
    s_original: AuthScheme,
    resolved: AuthScheme,
    json: Any | None = None,
) -> Dict[str, Any]:
    """
    Perform an authenticated request; if 401 and original is oauth2/form_login, try one refresh attempt.
    """
    snap = await client.request(method, url, auth_scheme=resolved, json=json)

    # Try refresh on 401 only once
    status = snap.get("response", {}).get("status") if "response" in snap else None
    if status == 401:
        if s_original.type == "oauth2":
            # attempt refresh, else re-fetch
            new_tok = await refresh_oauth2_token(s_original) or await fetch_oauth2_token(s_original)
            resolved.token = new_tok  # type: ignore[attr-defined]
            snap = await client.request(method, url, auth_scheme=resolved, json=json)
        elif s_original.type == "form_login":
            cookie = await perform_form_login(s_original)
            resolved.cookie = cookie  # type: ignore[attr-defined]
            snap = await client.request(method, url, auth_scheme=resolved, json=json)

    return snap


async def _probe_one(
    client: HttpClient,
    idx: int,
    ep: Endpoint,
    identities: List[AuthScheme],
    req_dir: Path,
) -> Tuple[ProbeSummaryRow, Dict[str, Any]]:
    """
    Fire no-auth and (optional) multiple-auth variants for a single endpoint.
    Save each snapshot to disk and build both legacy and RBAC-matrix summaries.
    """
    base_name = f"{idx:05d}_{ep.method}_{_safe_stem(ep.template or ep.url)}"
    body = ep.extra.get("body") if isinstance(ep.extra, dict) else None

    # 1) No-auth
    noauth_snap = await client.request(ep.method, ep.url, auth_scheme=None, json=body)
    noauth_path = req_dir / f"{base_name}__noauth.json"
    write_snapshot(noauth_snap, noauth_path)

    noauth_status = _resp_status(noauth_snap)
    noauth_size = _resp_size(noauth_snap)
    noauth_err = _error_msg(noauth_snap)

    # 2) With identities
    variants: Dict[str, VariantResult] = {"noauth": VariantResult(noauth_status, noauth_size, noauth_err)}

    # Legacy single-row (first identity if present)
    legacy_auth_name: Optional[str] = None
    legacy_auth_status: Optional[int] = None
    legacy_auth_size: Optional[int] = None

    for j, s in enumerate(identities):
        snap = await _authed_request_with_refresh(
            client,
            ep.method,
            ep.url,
            s_original=s,
            resolved=s,
            json=body,
        )
        auth_path = req_dir / f"{base_name}__auth_{_safe_stem(s.name)}.json"
        write_snapshot(snap, auth_path)

        stat = _resp_status(snap)
        sz = _resp_size(snap)
        err = _error_msg(snap)
        variants[s.name] = VariantResult(stat, sz, err)

        if j == 0:
            legacy_auth_name = s.name
            legacy_auth_status = stat
            legacy_auth_size = sz

    # Legacy row for back-compat with existing analysis/report
    legacy_row = ProbeSummaryRow(
        index=idx,
        method=ep.method,
        url=ep.url,
        requires_auth=ep.requires_auth,
        noauth_status=noauth_status,
        auth_name=legacy_auth_name,
        auth_status=legacy_auth_status,
        noauth_size=noauth_size or 0,
        auth_size=legacy_auth_size,
        notes=None,
    )

    # Matrix row (richer)
    matrix_row = {
        "index": idx,
        "method": ep.method,
        "url": ep.url,
        "requires_auth": ep.requires_auth,
        "variants": {
            name: {"status": vr.status, "size": vr.size, "error": vr.error}
            for name, vr in variants.items()
        },
    }

    return legacy_row, matrix_row


def _resp_status(snap: Dict[str, Any]) -> Optional[int]:
    if "response" in snap:
        return int(snap["response"]["status"])
    return None


def _resp_size(snap: Dict[str, Any]) -> Optional[int]:
    if "response" in snap:
        return int(snap["response"]["body"]["size"] or 0)
    return None


def _error_msg(snap: Dict[str, Any]) -> Optional[str]:
    if "error" in snap:
        return f"{snap['error'].get('type')}: {snap['error'].get('message')}"
    return None
