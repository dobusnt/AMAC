from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

try:  # Use PyYAML if available, else fall back to internal minimal parser
    import yaml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback
    from .. import _yaml as yaml

from ..config import choose_base_urls, is_url_in_scope, is_url_path_allowed
from ..models import Endpoint, EndpointSet, ScopeConfig
from .sampler import fill_server_variables, sample_param_value

# -----------------------------
# Loaders
# -----------------------------

async def _load_spec(src: str) -> Dict[str, Any]:
    """Load an OpenAPI doc from a local path or HTTP(S) URL (JSON or YAML)."""
    if src.lower().startswith(("http://", "https://")):
        try:  # Import httpx only when needed
            import httpx  # type: ignore
        except ModuleNotFoundError as e:  # pragma: no cover
            raise RuntimeError("httpx is required to fetch remote OpenAPI documents") from e
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(src)
            r.raise_for_status()
            text = r.text
    else:
        text = Path(src).read_text(encoding="utf-8")

    # try JSON first, then YAML
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("OpenAPI file must be a JSON/YAML object")
        return data


# -----------------------------
# Ref resolution (very small)
# -----------------------------

def _resolve_local_ref(doc: Dict[str, Any], ref: str) -> Any:
    """
    Resolve a local JSON pointer like "#/components/schemas/User".
    External refs (URLs, files) are not supported in MVP.
    """
    if not ref.startswith("#/"):
        # naive: skip external
        return {"$ref": ref}
    parts = ref[2:].split("/")
    cur: Any = doc
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return {"$ref": ref}
    return cur


def _deref(obj: Any, doc: Dict[str, Any]) -> Any:
    if isinstance(obj, dict) and "$ref" in obj:
        return _deref(_resolve_local_ref(doc, obj["$ref"]), doc)
    return obj


# -----------------------------
# Security inheritance helpers
# -----------------------------

def _operation_requires_auth(doc: Dict[str, Any], path_item: Dict[str, Any], op_obj: Dict[str, Any]) -> Optional[bool]:
    """
    Return True/False/None whether operation declares auth (security requirement).
    Rules:
      - If operation.security == [] → explicitly no auth (False)
      - If operation.security is non-empty → True
      - Else inherit from path_item.security or root.security
      - If nothing present → None
    """
    def has_sec(node) -> Optional[bool]:
        if not isinstance(node, dict):
            return None
        if "security" not in node:
            return None
        sec = node.get("security")
        if sec == []:
            return False
        if isinstance(sec, list) and len(sec) > 0:
            return True
        return None

    for n in (op_obj, path_item, doc):
        v = has_sec(n)
        if v is not None:
            return v
    return None


# -----------------------------
# URL building with servers[]
# -----------------------------

def _server_urls(doc: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    servers = doc.get("servers") or []
    for s in servers:
        if not isinstance(s, dict):
            continue
        u = fill_server_variables(s)
        if u:
            urls.append(u.rstrip("/"))
    return urls


def _path_servers(path_item: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    servers = path_item.get("servers") or []
    for s in servers:
        if not isinstance(s, dict):
            continue
        u = fill_server_variables(s)
        if u:
            urls.append(u.rstrip("/"))
    return urls


# -----------------------------
# Parameter handling
# -----------------------------

def _collect_params(doc: Dict[str, Any], path_item: Dict[str, Any], op_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Merge path-level and operation-level params, deref any $ref.
    """
    params: List[Dict[str, Any]] = []
    for node in (path_item, op_obj):
        for p in node.get("parameters", []) or []:
            p2 = _deref(p, doc)
            if isinstance(p2, dict):
                params.append(p2)
    return params


def _apply_path_template(path_template: str, params: List[Dict[str, Any]]) -> str:
    """
    Replace /users/{id} with a sampled value.
    """
    out = path_template
    for p in params:
        if p.get("in") == "path" and p.get("required", True):
            name = p.get("name", "")
            val = sample_param_value(p)
            out = out.replace("{" + str(name) + "}", str(val))
    return out


def _build_query(params: List[Dict[str, Any]]) -> str:
    """Build a query string for required or defaulted query parameters."""
    items: List[str] = []
    for p in params:
        if p.get("in") != "query":
            continue
        schema = p.get("schema") or {}
        has_default = isinstance(schema, dict) and "default" in schema
        if p.get("required", False) or has_default:
            name = str(p.get("name", "q"))
            val = sample_param_value(p)
            items.append(f"{name}={val}")
    return ("?" + "&".join(items)) if items else ""


# -----------------------------
# Main mapping
# -----------------------------

async def load_and_map_openapi(openapi_src: str, scope: ScopeConfig) -> EndpointSet:
    """
    Load OpenAPI → build EndpointSet of GET/HEAD URLs (with sampled required parameters).
    Handles:
      - servers[] and path-level servers (with {variables})
      - $ref for components/parameters (local pointers)
      - inherited security (root → path → operation)
      - oneOf/anyOf in param schemas (first branch)
    """
    doc = await _load_spec(openapi_src)

    # Determine base URLs (servers from spec or scope.base_urls)
    server_urls = _server_urls(doc)
    base_urls = choose_base_urls(scope, server_urls)

    endpoints: List[Endpoint] = []

    paths = doc.get("paths") or {}
    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Servers override for this path
        base_for_path = _path_servers(path_item) or base_urls

        for method in ("get", "head"):
            if method not in path_item:
                continue
            op_obj = path_item[method]
            if not isinstance(op_obj, dict):
                continue

            # Security inherited
            req_auth = _operation_requires_auth(doc, path_item, op_obj)

            # Params
            params = _collect_params(doc, path_item, op_obj)
            # Build concrete path with substitutions + required query
            concrete_path = _apply_path_template(str(raw_path), params)
            query = _build_query(params)

            # Resulting URLs for each server
            for b in base_for_path:
                full = urljoin(b.rstrip("/") + "/", concrete_path.lstrip("/")) + query

                # Host-level and path-level scope gates
                if not is_url_in_scope(full, scope):
                    continue
                if not is_url_path_allowed(full, scope):
                    continue

                # tags + operationId
                tags = op_obj.get("tags") or []
                op_id = op_obj.get("operationId")

                endpoints.append(
                    Endpoint(
                        method=method.upper(),  # type: ignore[arg-type]
                        url=full,
                        requires_auth=req_auth,
                        template=str(raw_path),
                        tags=tags if isinstance(tags, list) else [],
                        operation_id=str(op_id) if op_id else None,
                    )
                )

    # Deduplicate (method,url)
    seen = set()
    uniq: List[Endpoint] = []
    for ep in endpoints:
        key = (ep.method, ep.url)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(ep)

    return EndpointSet(endpoints=uniq)
