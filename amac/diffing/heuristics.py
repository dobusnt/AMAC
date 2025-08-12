from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Dict

from .._json import dumps

REDACT_HEADER_KEYS = {"authorization", "proxy-authorization", "cookie", "x-api-key", "api-key"}


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in REDACT_HEADER_KEYS or lk.startswith("x-auth"):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def write_snapshot(obj: Any, path: Path) -> None:
    """
    Write a JSON snapshot to disk (pretty). Accepts pydantic models or dicts.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "model_dump"):
        payload = obj.model_dump()
    else:
        payload = obj
    path.write_bytes(dumps(payload))


def package_evidence_dir(evidence_dir: Path, out_zip: Path) -> Path:
    """
    Create a zip of the evidence directory (e.g., run_dir/requests).
    """
    evidence_dir = Path(evidence_dir)
    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in evidence_dir.rglob("*"):
            if p.is_file():
                z.write(p, arcname=p.relative_to(evidence_dir.parent))
    return out_zip
