from __future__ import annotations

import asyncio
from pathlib import Path
import json

from amac.config import load_scope_config
from amac.discovery.openapi import load_and_map_openapi


def test_map_openapi_local():
    """
    Sanity test: the local demo OpenAPI should map to 4 endpoints (HEAD /status,
    GET /users/me, GET /users/{id} -> 1, GET /search?q=test&page=1) against 127.0.0.1:8008.
    """
    repo_root = Path(__file__).resolve().parents[1]
    openapi_path = str(repo_root / "examples" / "openapi_local.json")
    scope_path = str(repo_root / "examples" / "scope_local.yml")

    scope_cfg = load_scope_config(scope_path)
    es = asyncio.run(load_and_map_openapi(openapi_path, scope_cfg))

    assert len(es.endpoints) == 4, f"expected 4 endpoints, got {len(es.endpoints)}"

    got = {(e.method, e.url) for e in es.endpoints}
    expected = {
        ("HEAD", "http://127.0.0.1:8008/status"),
        ("GET", "http://127.0.0.1:8008/users/me"),
        ("GET", "http://127.0.0.1:8008/users/1"),
        ("GET", "http://127.0.0.1:8008/search?q=test&page=1"),
    }
    assert got == expected, f"unexpected endpoints:\nGot: {got}\nExpected: {expected}"


def test_map_openapi_post_body(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Demo", "version": "1.0"},
        "paths": {
            "/items": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))

    scope_path = tmp_path / "scope.yml"
    scope_path.write_text(
        "allowed:\n  - example.com\nbase_urls:\n  - https://example.com\nrequest_policy:\n  safe_methods_only: false\n  non_safe_methods:\n    - POST\n"
    )

    scope_cfg = load_scope_config(str(scope_path))
    es = asyncio.run(load_and_map_openapi(str(spec_path), scope_cfg))

    assert {(e.method, e.url) for e in es.endpoints} == {(
        "POST",
        "https://example.com/items",
    )}
    body = es.endpoints[0].extra.get("body")
    assert body == {"name": "alice"}
