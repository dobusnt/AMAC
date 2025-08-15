from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, Optional

_UUID = "00000000-0000-4000-8000-000000000000"
_EMAIL = "user@example.com"
_DATE = _dt.date(2024, 1, 2).isoformat()
_DATETIME = _dt.datetime(2024, 1, 2, 3, 4, 5).isoformat() + "Z"


def _pick_enum(values: list[Any]) -> Any:
    # prefer a non-empty string/number, else first
    for v in values:
        if isinstance(v, (str, int, float)) and str(v):
            return v
    return values[0] if values else None


def _coerce_number(schema: Dict[str, Any], fallback: int | float = 1) -> int | float:
    if "example" in schema and isinstance(schema["example"], (int, float)):
        return schema["example"]
    if "default" in schema and isinstance(schema["default"], (int, float)):
        return schema["default"]
    mn = schema.get("minimum")
    mx = schema.get("maximum")
    if isinstance(mn, (int, float)) and isinstance(mx, (int, float)):
        try:
            return (mn + mx) / 2
        except Exception:
            return mn
    if isinstance(mn, (int, float)):
        return mn
    if isinstance(mx, (int, float)):
        return mx
    return fallback


def _coerce_string(schema: Dict[str, Any], name_hint: str | None = None) -> str:
    fmt = str(schema.get("format") or "").lower()
    ex = schema.get("example")
    if isinstance(ex, str) and ex:
        return ex
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        v = _pick_enum(schema["enum"])
        return str(v)
    if fmt == "uuid":
        return _UUID
    if fmt in ("date",):
        return _DATE
    if fmt in ("date-time", "datetime", "rfc3339"):
        return _DATETIME
    if fmt in ("email",):
        return _EMAIL
    if fmt in ("uri", "url"):
        return "https://example.com"
    # if a hint suggests id/user/page, bias to simple demo values
    if name_hint:
        n = name_hint.lower()
        if n in ("id", "user_id", "uid"):
            return "1"
        if n in ("page", "p"):
            return "1"
        if "name" in n:
            return "alice"
        if "query" in n or n in ("q", "search"):
            return "test"
    # minLength/maximumHints ignored for MVP
    return "1"


def _coerce_boolean(schema: Dict[str, Any]) -> bool:
    if "example" in schema and isinstance(schema["example"], bool):
        return schema["example"]
    if "default" in schema and isinstance(schema["default"], bool):
        return schema["default"]
    return True


def sample_param_value(param: Dict[str, Any]) -> str:
    """
    Produce a realistic demo value for a parameter using schema hints.
    """
    schema = param.get("schema") or {}
    typ = str(schema.get("type") or "").lower()
    name = str(param.get("name") or "")
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return str(_pick_enum(schema["enum"]))
    if typ in ("integer", "number"):
        return str(_coerce_number(schema))
    if typ in ("boolean",):
        return "true" if _coerce_boolean(schema) else "false"
    # Handle oneOf/anyOf quickly
    for key in ("oneOf", "anyOf"):
        if key in schema and isinstance(schema[key], list) and schema[key]:
            first = schema[key][0] or {}
            if "type" in first:
                return sample_param_value({"name": name, "schema": first})
    # string or unknown
    return _coerce_string(schema, name_hint=name)


def sample_schema_value(schema: Dict[str, Any], name_hint: str | None = None) -> Any:
    """Sample a value for a JSON schema object (for request bodies)."""
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return _pick_enum(schema["enum"])

    typ = str(schema.get("type") or "").lower()
    if typ == "object":
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        out: Dict[str, Any] = {}
        for k, v in props.items():
            if required and k not in required:
                continue
            if isinstance(v, dict):
                out[k] = sample_schema_value(v, name_hint=k)
        return out
    if typ == "array":
        items = schema.get("items") or {}
        if isinstance(items, dict):
            return [sample_schema_value(items)]
        return []
    if typ in ("integer", "number"):
        return _coerce_number(schema)
    if typ == "boolean":
        return _coerce_boolean(schema)

    for key in ("oneOf", "anyOf"):
        if key in schema and isinstance(schema[key], list) and schema[key]:
            first = schema[key][0] or {}
            if isinstance(first, dict):
                return sample_schema_value(first, name_hint=name_hint)

    return _coerce_string(schema, name_hint=name_hint)


def fill_server_variables(server_obj: Dict[str, Any]) -> Optional[str]:
    """
    Expand a single OpenAPI server object with variables, picking the first enum/default.
    """
    url = server_obj.get("url")
    if not isinstance(url, str) or not url:
        return None
    vars = server_obj.get("variables") or {}
    for var_name, var_spec in vars.items():
        rep = None
        if isinstance(var_spec, dict):
            if "enum" in var_spec and isinstance(var_spec["enum"], list) and var_spec["enum"]:
                rep = str(var_spec["enum"][0])
            elif "default" in var_spec:
                rep = str(var_spec["default"])
        if rep is None:
            rep = ""  # fallback: empty
        url = url.replace("{" + var_name + "}", rep)
    return url
