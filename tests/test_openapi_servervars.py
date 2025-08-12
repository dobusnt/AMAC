from __future__ import annotations

import asyncio
from pathlib import Path

from amac.config import load_scope_config
from amac.discovery.openapi import load_and_map_openapi


def test_server_variables_and_param_sampling():
    """
    Verifies:
      - servers[] with {variables} expands using default
      - required path/query params are sampled into the URL
    """
    repo_root = Path(__file__).resolve().parents[1]
    spec = str(repo_root / "examples" / "openapi_servervars.json")
    scope = str(repo_root / "examples" / "scope_servervars.yml")

    scope_cfg = load_scope_config(scope)
    es = asyncio.run(load_and_map_openapi(spec, scope_cfg))

    assert len(es.endpoints) == 1
    ep = es.endpoints[0]
    assert ep.method == "GET"
    # server var default is "dev" → host api.dev.local
    assert ep.url.startswith("https://api.dev.local/v1/users/")
    # required query param 'q' should appear
    assert "?q=" in ep.url
