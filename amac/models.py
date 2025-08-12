from __future__ import annotations

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator


# -----------------------------
# Privacy / evidence
# -----------------------------

PrivacyLevel = Literal["none", "minimal", "strict"]


class EvidencePolicy(BaseModel):
    privacy_level: PrivacyLevel = Field(
        default="minimal",
        description="Controls PII redaction in snippets/headers: none|minimal|strict.",
    )
    # in the future we can add custom redaction patterns here


# -----------------------------
# Request / pacing / scope
# -----------------------------

class RequestPolicy(BaseModel):
    safe_methods_only: bool = Field(
        default=True,
        description="If true, only emit safe HTTP methods (GET/HEAD) in MVP.",
    )
    max_rps: int = Field(
        default=2, ge=1, description="Maximum requests per second across all hosts."
    )
    concurrency: int = Field(
        default=4, ge=1, description="Maximum in-flight requests (global)."
    )
    per_host_concurrency: int = Field(
        default=2, ge=1, description="Max in-flight requests per host."
    )
    global_jitter_ms: int = Field(
        default=60, ge=0, description="Extra random sleep [0..jitter] ms before requests."
    )
    backoff_cap_s: float = Field(
        default=4.0, ge=0.1, description="Upper cap for exponential backoff sleeps."
    )
    allow_redirects: bool = Field(
        default=False, description="Follow redirects during probes (safer default: false)."
    )
    verify_tls: bool = Field(
        default=True, description="Verify TLS certificates for https requests."
    )
    hard_request_budget: int = Field(
        default=0,
        ge=0,
        description="Hard cap on total requests this run (0 = unlimited).",
    )


class Timeouts(BaseModel):
    connect: int = Field(default=5, ge=1, description="Connect timeout seconds.")
    read: int = Field(default=15, ge=1, description="Read timeout seconds.")


class PathPolicy(BaseModel):
    allow_paths: List[str] = Field(
        default_factory=list,
        description="Optional glob/regex-like patterns to ALLOW (match against URL path). Empty = allow all.",
    )
    deny_paths: List[str] = Field(
        default_factory=list,
        description="Optional glob/regex-like patterns to DENY (evaluated before allow_paths).",
    )

    @field_validator("allow_paths", "deny_paths", mode="before")
    @classmethod
    def _norm_paths(cls, v: Any) -> Any:
        if v is None:
            return []
        if not isinstance(v, list):
            raise TypeError("allow_paths/deny_paths must be lists of strings")
        out = []
        for s in v:
            if not isinstance(s, str):
                raise TypeError("path patterns must be strings")
            s2 = s.strip()
            if s2:
                out.append(s2)
        return out


class ScopeConfig(BaseModel):
    allowed: List[str] = Field(
        default_factory=list,
        description='Host allowlist, supports wildcards like "*.example.com".',
    )
    base_urls: List[str] = Field(
        default_factory=list,
        description="Absolute base URLs for targets (e.g., https://api.example.com).",
    )
    denied: List[str] = Field(
        default_factory=list,
        description='Host denylist, supports wildcards like "admin.example.com".',
    )
    # New: per-path allow/deny and evidence policy
    path_policy: PathPolicy = Field(default_factory=PathPolicy)
    request_policy: RequestPolicy = Field(default_factory=RequestPolicy)
    timeouts: Timeouts = Field(default_factory=Timeouts)
    evidence: EvidencePolicy = Field(default_factory=EvidencePolicy)
    evidence_dir: str = Field(default="./evidence")

    @field_validator("allowed", "denied", mode="before")
    @classmethod
    def _normalize_host_patterns(cls, v: Any) -> Any:
        if v is None:
            return []
        if not isinstance(v, list):
            raise TypeError("expected a list of strings")
        out = []
        for s in v:
            if not isinstance(s, str):
                raise TypeError("host pattern entries must be strings")
            s2 = s.strip().lower()
            if s2:
                out.append(s2)
        return out

    @field_validator("base_urls", mode="before")
    @classmethod
    def _normalize_base_urls(cls, v: Any) -> Any:
        if v is None:
            return []
        if not isinstance(v, list):
            raise TypeError("base_urls must be a list of absolute URLs")
        out = []
        for s in v:
            if not isinstance(s, str):
                raise TypeError("base_urls entries must be strings")
            s2 = s.strip()
            if s2:
                out.append(s2)
        return out


# -----------------------------
# Auth models (auth.yml)
# -----------------------------

AuthType = Literal["bearer", "cookie", "basic", "header", "oauth2", "form_login"]


class AuthScheme(BaseModel):
    name: str = Field(..., description="Human-friendly identity name.")
    type: AuthType

    # bearer/header
    token: Optional[str] = Field(
        default=None, description="Raw token string for bearer/header types."
    )
    header: str = Field(
        default="Authorization",
        description='Header key for bearer/header types, e.g. "Authorization"',
    )

    # cookie
    cookie: Optional[str] = Field(
        default=None,
        description='Cookie string for cookie-based auth, e.g. "SESSIONID=abc123; Path=/; Secure".',
    )

    # basic
    username: Optional[str] = None
    password: Optional[str] = None

    # oauth2 (client credentials / password / refresh)
    token_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = Field(default=None, description="Space-delimited scopes string.")
    audience: Optional[str] = None
    grant_type: Optional[Literal["client_credentials", "password"]] = None
    refresh_token: Optional[str] = None  # for refresh flow (if provided)

    # form_login (cookie capture via POST)
    login_url: Optional[str] = None
    login_method: Literal["POST", "GET"] = "POST"
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    extra_fields: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_by_type(self) -> "AuthScheme":
        t = self.type
        if t == "bearer":
            if not self.token:
                raise ValueError("bearer auth requires `token`")
        elif t == "cookie":
            if not self.cookie:
                raise ValueError("cookie auth requires `cookie`")
        elif t == "basic":
            if not (self.username and self.password):
                raise ValueError("basic auth requires `username` and `password`")
        elif t == "header":
            if not (self.header and self.token):
                raise ValueError("header auth requires `header` and `token`")
        elif t == "oauth2":
            if not self.token_url:
                raise ValueError("oauth2 requires `token_url`")
            if self.grant_type not in ("client_credentials", "password"):
                raise ValueError("oauth2.grant_type must be client_credentials or password")
            if self.grant_type == "client_credentials":
                if not (self.client_id and self.client_secret):
                    raise ValueError("oauth2 client_credentials requires client_id and client_secret")
            if self.grant_type == "password":
                if not (self.client_id and self.client_secret and self.username and self.password):
                    raise ValueError(
                        "oauth2 password grant requires client_id, client_secret, username, password"
                    )
        elif t == "form_login":
            if not (self.login_url and self.username_field and self.password_field and self.username and self.password):
                raise ValueError(
                    "form_login requires login_url, username_field, password_field, username, password"
                )
        return self


class AuthConfig(BaseModel):
    auth_schemes: List[AuthScheme] = Field(default_factory=list)


# -----------------------------
# Endpoint & mapping models
# -----------------------------

HttpMethod = Literal["GET", "HEAD"]  # MVP scope


class Endpoint(BaseModel):
    method: HttpMethod
    url: str
    requires_auth: Optional[bool] = Field(
        default=None,
        description="Whether OpenAPI declares auth required for this operation (None if unknown).",
    )
    template: Optional[str] = Field(
        default=None,
        description="Original templated path like /users/{id} if applicable.",
    )
    source: Literal["openapi"] = "openapi"
    tags: List[str] = Field(default_factory=list)
    operation_id: Optional[str] = None

    extra: Dict[str, Any] = Field(
        default_factory=dict, description="Room for future fields without breaking schema."
    )


class EndpointSet(BaseModel):
    """
    Container used when writing endpoints.json (handy for future metadata).
    """
    generated_by: str = "amac"
    version: str = "0.1.0"
    endpoints: List[Endpoint] = Field(default_factory=list)
