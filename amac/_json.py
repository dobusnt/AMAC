from __future__ import annotations

import json as _json_std
from typing import Any

try:  # pragma: no cover - optional dependency
    import orjson as _json_fast  # type: ignore
except Exception:  # pragma: no cover
    def dumps(obj: Any, *, indent: int = 2) -> bytes:
        return _json_std.dumps(obj, indent=indent).encode()

    def loads(data: bytes | bytearray | str) -> Any:
        if isinstance(data, (bytes, bytearray)):
            data = data.decode()
        return _json_std.loads(data)
else:  # pragma: no cover
    def dumps(obj: Any, *, indent: int = 2) -> bytes:
        option = _json_fast.OPT_INDENT_2 if indent == 2 else 0
        return _json_fast.dumps(obj, option=option)

    def loads(data: bytes | bytearray | str) -> Any:
        return _json_fast.loads(data)

__all__ = ["dumps", "loads"]
