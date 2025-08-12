import os
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse


try:  # Prefer PyYAML but fall back to minimal parser
    import yaml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for environments without PyYAML
    from . import _yaml as yaml

try:  # Optional pydantic for rich validation
    from pydantic import ValidationError  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback when pydantic missing
    ValidationError = Exception  # type: ignore

from .models import (
    AuthConfig,
    AuthScheme,
    EvidencePolicy,
    PathPolicy,
    RequestPolicy,
    ScopeConfig,
    Timeouts,
)

# -----------------------------
# YAML loaders
# -----------------------------

def _read_yaml(path: str | os.PathLike) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"YAML file not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping/object: {p}")
    return data


# -----------------------------
# Config loaders
# -----------------------------

def load_scope_config(path: str | os.PathLike) -> ScopeConfig:
    """Load and validate scope.yml into a ScopeConfig."""
    raw = _read_yaml(path)
    if hasattr(ScopeConfig, "model_validate"):
        try:
            cfg = ScopeConfig.model_validate(raw)
        except ValidationError as ve:
            raise ValueError(f"Invalid scope config {path}:\n{ve}") from ve
    else:  # dataclass fallback
        allowed = [str(s).strip().lower() for s in raw.get("allowed", []) or []]
        base_urls = [str(s).strip() for s in raw.get("base_urls", []) or []]
        denied = [str(s).strip().lower() for s in raw.get("denied", []) or []]
        pp_raw = raw.get("path_policy", {}) or {}
        path_policy = PathPolicy(
            allow_paths=[str(s).strip() for s in pp_raw.get("allow_paths", []) or []],
            deny_paths=[str(s).strip() for s in pp_raw.get("deny_paths", []) or []],
        )
        rp = RequestPolicy(**(raw.get("request_policy", {}) or {}))
        to = Timeouts(**(raw.get("timeouts", {}) or {}))
        ev = EvidencePolicy(**(raw.get("evidence", {}) or {}))
        cfg = ScopeConfig(
            allowed=allowed,
            base_urls=base_urls,
            denied=denied,
            path_policy=path_policy,
            request_policy=rp,
            timeouts=to,
            evidence=ev,
            evidence_dir=str(raw.get("evidence_dir", "./evidence")),
        )

    if not cfg.allowed and not cfg.base_urls:
        raise ValueError(
            "scope.yml must specify at least one of `allowed` hosts or `base_urls`.",
        )
    return cfg


def load_auth_config(path: str | os.PathLike) -> AuthConfig:
    """Load and validate auth.yml into an AuthConfig."""
    raw = _read_yaml(path)
    if hasattr(AuthConfig, "model_validate"):
        try:
            cfg = AuthConfig.model_validate(raw)
        except ValidationError as ve:
            raise ValueError(f"Invalid auth config {path}:\n{ve}") from ve
    else:  # dataclass fallback
        schemes_raw = raw.get("auth_schemes", []) or []
        schemes: List[AuthScheme] = []
        for item in schemes_raw:
            if isinstance(item, dict):
                name = str(item.get("name", ""))
                atype = str(item.get("type", ""))
                if name and atype:
                    schemes.append(AuthScheme(name=name, type=atype))
        cfg = AuthConfig(auth_schemes=schemes)

    if not cfg.auth_schemes:
        raise ValueError("auth.yml must contain at least one auth scheme in `auth_schemes`.")
    return cfg


# -----------------------------
# Scope & path matching helpers
# -----------------------------

def _host_from_url(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        raise ValueError(f"Invalid absolute URL (no hostname): {url}")
    return host.lower()


def _path_from_url(url: str) -> str:
    return urlparse(url).path or "/"


def _host_matches(pattern: str, host: str) -> bool:
    """
    Wildcard match where pattern may begin with "*.".
    Examples:
      pattern="example.com" matches "example.com" only.
      pattern="*.example.com" matches "a.example.com", "b.c.example.com" but NOT "example.com".
    """
    pattern = pattern.lower()
    host = host.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # keep the dot, e.g. ".example.com"
        return host.endswith(suffix) and host != pattern[2:]  # not the naked domain
    else:
        return host == pattern


def any_match(patterns: Iterable[str], host: str) -> bool:
    return any(_host_matches(p, host) for p in patterns)


def is_url_in_scope(url: str, scope: ScopeConfig) -> bool:
    """Check if the URL's host is permitted by allowed/denied lists."""
    host = _host_from_url(url)
    if scope.denied and any_match(scope.denied, host):
        return False
    if scope.allowed:
        return any_match(scope.allowed, host)
    # If `allowed` is empty but base_urls were provided, allow hosts from base_urls.
    base_hosts = {_host_from_url(u) for u in scope.base_urls}
    return host in base_hosts


# -------- per-path allow/deny ------------------------------------------------

def _path_allowed_by_patterns(path: str, allow_patterns: Iterable[str], deny_patterns: Iterable[str]) -> bool:
    """
    Return True if the given URL path passes deny → allow checks.
    Pattern semantics:
      - If pattern starts with 're:' treat the remainder as a regular expression (search).
      - Otherwise use glob-style matching (fnmatch), case-sensitive per URL norm.
    """
    # Deny takes precedence
    for pat in deny_patterns:
        if _path_pattern_match(path, pat):
            return False

    # If no allow rules, default allow; else require at least one allow match
    if not list(allow_patterns):
        return True

    return any(_path_pattern_match(path, pat) for pat in allow_patterns)


def _path_pattern_match(path: str, pattern: str) -> bool:
    if pattern.startswith("re:"):
        try:
            return re.search(pattern[3:], path) is not None
        except re.error:
            return False
    # normalize to start with '/' for consistency
    norm = path if path.startswith("/") else "/" + path
    pat = pattern if pattern.startswith("/") or pattern.startswith("re:") else "/" + pattern
    return fnmatch(norm, pat)


def is_url_path_allowed(url: str, scope: ScopeConfig) -> bool:
    path = _path_from_url(url)
    pol = scope.path_policy
    return _path_allowed_by_patterns(path, pol.allow_paths, pol.deny_paths)


def assert_urls_in_scope(urls: Iterable[str], scope: ScopeConfig) -> None:
    """Raise if any URL falls outside of host scope or path policy."""
    out_of_scope = [u for u in urls if not is_url_in_scope(u, scope)]
    if out_of_scope:
        joined = "\n  - ".join(out_of_scope[:20])
        more = "" if len(out_of_scope) <= 20 else f"\n  (+{len(out_of_scope)-20} more)"
        raise ValueError(
            "Some endpoints are outside of HOST scope. Update scope.yml (allowed/denied/base_urls).\n  - " + joined + more
        )

    path_blocked = [u for u in urls if not is_url_path_allowed(u, scope)]
    if path_blocked:
        joined = "\n  - ".join(path_blocked[:20])
        more = "" if len(path_blocked) <= 20 else f"\n  (+{len(path_blocked)-20} more)"
        raise ValueError(
            "Some endpoints are blocked by PATH policy (deny_paths/allow_paths). "
            "Adjust scope.yml:path_policy.\n  - " + joined + more
        )


# -----------------------------
# Base URL selection
# -----------------------------

def choose_base_urls(scope: ScopeConfig, openapi_servers: list[str] | None) -> list[str]:
    """
    Determine the effective base URLs to use for OpenAPI expansion:
    - Prefer servers[] from the spec if present.
    - Otherwise fall back to scope.base_urls.
    """
    if openapi_servers:
        return openapi_servers
    if scope.base_urls:
        return scope.base_urls
    raise ValueError(
        "No servers[] found in OpenAPI and no `base_urls` in scope.yml. "
        "Specify at least one base URL."
    )
