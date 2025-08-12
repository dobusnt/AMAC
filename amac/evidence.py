from __future__ import annotations

from pathlib import Path
from typing import Any

from ._json import dumps


def write_snapshot(obj: Any, path: Path) -> None:
    """Write a request/response snapshot to disk as pretty JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "model_dump"):
        payload = obj.model_dump()
    else:
        try:
            payload = obj.__dict__  # dataclasses etc.
        except Exception:
            payload = obj
    path.write_bytes(dumps(payload))

__all__ = ["write_snapshot"]
