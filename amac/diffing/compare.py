from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import orjson


@dataclass
class Finding:
    type: str
    severity: str
    method: str
    url: str
    requires_auth: Optional[bool]
    noauth_status: Optional[int]
    auth_status: Optional[int]
    delta_size: Optional[int]
    notes: str


def _load_json(path: Path) -> Dict[str, Any]:
    return orjson.loads(path.read_bytes())


def _dump_json(obj: Any, path: Path) -> None:
    path.write_bytes(orjson.dumps(obj, option=orjson.OPT_INDENT_2))


def _pct_diff(a: int, b: int) -> float:
    if a == 0 and b == 0:
        return 0.0
    base = max(1, min(a, b))
    return abs(a - b) / base


def _classify_row(r: Dict[str, Any]) -> List[Finding]:
    """
    Heuristic classification based on statuses and body sizes only (MVP).
    Later we can enrich with snapshot body keys/diffs.
    """
    findings: List[Finding] = []

    method = str(r.get("method", "GET"))
    url = str(r.get("url", ""))
    requires_auth = r.get("requires_auth", None)

    no_s = r.get("noauth_status")
    au_s = r.get("auth_status")
    no_sz = int(r.get("noauth_size") or 0)
    au_sz = int(r.get("auth_size") or 0)
    dsz = au_sz - no_sz if (au_s is not None and no_s is not None) else None

    # Helper to append
    def add(ftype: str, sev: str, notes: str) -> None:
        findings.append(
            Finding(
                type=ftype,
                severity=sev,
                method=method,
                url=url,
                requires_auth=requires_auth,
                noauth_status=no_s if isinstance(no_s, int) else None,
                auth_status=au_s if isinstance(au_s, int) else None,
                delta_size=dsz,
                notes=notes,
            )
        )

    # Only consider rows where we have at least no-auth status
    if no_s is None:
        return findings

    # 1) If OpenAPI declares auth required:
    if requires_auth is True:
        if no_s in (200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308):
            add(
                "UNEXPECTED_2XX_OR_3XX_UNAUTH",
                "high",
                "Spec declares auth required but unauthenticated request did not return 401/403.",
            )
        elif no_s not in (401, 403):
            add(
                "UNEXPECTED_STATUS_UNAUTH",
                "medium",
                f"Spec declares auth required; expected 401/403 unauthenticated but got {no_s}.",
            )

        # Similar sized bodies between auth and no-auth could indicate leakage
        if isinstance(au_s, int) and au_s in (200, 206) and no_s in (200, 206):
            # treat within 10% size as suspicious similarity
            if _pct_diff(no_sz, au_sz) <= 0.10:
                add(
                    "POSSIBLE_CONTENT_LEAK",
                    "medium",
                    "Authenticated vs unauthenticated responses look very similar in size (<=10% diff).",
                )

    # 2) If auth not declared (unknown), still flag obvious smells
    if requires_auth in (None, False):
        # If unauthenticated returns 200 but authenticated returns 401/403: odd (token breaks?)
        if isinstance(au_s, int) and au_s in (401, 403) and no_s in (200, 206):
            add(
                "AUTH_REGRESSION_WITH_TOKEN",
                "low",
                "Unauthenticated is OK but adding auth caused 401/403; may be a broken token or header.",
            )

        # Similarity between auth/no-auth for endpoints likely private (URL hints)
        if isinstance(au_s, int) and au_s in (200, 206) and no_s in (200, 206):
            if _pct_diff(no_sz, au_sz) <= 0.05 and any(
                key in url.lower() for key in ("/me", "/admin", "/profile", "/private")
            ):
                add(
                    "SUSPECT_PRIVATE_ENDPOINT_OPEN",
                    "medium",
                    "Endpoint name suggests private resource but unauthenticated body matches authenticated closely.",
                )

    # 3) General catch: 401/403 unauth and 200 auth is normal → no finding
    return findings


def analyze_summary(summary_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a findings object from a probe run summary.json.
    """
    rows: List[Dict[str, Any]] = summary_json.get("rows", [])
    all_findings: List[Finding] = []
    for r in rows:
        all_findings.extend(_classify_row(r))

    # Counts by type and severity
    type_counts: Dict[str, int] = {}
    sev_counts: Dict[str, int] = {}
    for f in all_findings:
        type_counts[f.type] = type_counts.get(f.type, 0) + 1
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return {
        "version": "0.1.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "counts": {
            "total_endpoints": len(rows),
            "total_findings": len(all_findings),
            "by_type": type_counts,
            "by_severity": sev_counts,
        },
        "findings": [asdict(f) for f in all_findings],
    }


def analyze_run_dir(run_dir: Path) -> Tuple[Path, Path]:
    """
    Load {run_dir}/summary.json, write findings.json and a simple findings.md.
    Returns (findings_json_path, findings_md_path).
    """
    run_dir = Path(run_dir)
    summary_path = run_dir / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"summary.json not found under: {run_dir}")

    summary = _load_json(summary_path)
    findings = analyze_summary(summary)

    # Write JSON
    findings_json = run_dir / "findings.json"
    _dump_json(findings, findings_json)

    # Write a tiny Markdown overview
    md_lines: List[str] = []
    md_lines.append(f"# Findings — AMAC\n")
    md_lines.append(f"- Generated: {findings['generated_at']}")
    counts = findings["counts"]
    md_lines.append(f"- Endpoints analyzed: {counts['total_endpoints']}")
    md_lines.append(f"- Findings: {counts['total_findings']}\n")

    if findings["findings"]:
        md_lines.append("## Items\n")
        for i, f in enumerate(findings["findings"], 1):
            md_lines.append(
                f"{i}. **{f['severity'].upper()}** — {f['type']}  \n"
                f"   `{f['method']} {f['url']}`  \n"
                f"   no-auth: {f.get('noauth_status')} → auth: {f.get('auth_status')}  \n"
                f"   Δsize: {f.get('delta_size')}  \n"
                f"   _{f.get('notes','')}_\n"
            )
    else:
        md_lines.append("_No findings under current heuristics._\n")

    findings_md = run_dir / "findings.md"
    findings_md.write_text("\n".join(md_lines), encoding="utf-8")

    return findings_json, findings_md


# If you want to run this module directly:
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Analyze AMAC probe run directory.")
    ap.add_argument("run_dir", type=str, help="Path to run directory (contains summary.json)")
    args = ap.parse_args()

    fj, fm = analyze_run_dir(Path(args.run_dir))
    print(f"Wrote:\n  {fj}\n  {fm}")
