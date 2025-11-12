from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

try:  # Prefer real Pydantic models
    from pydantic import BaseModel, Field, field_validator, model_validator
    _USE_PYDANTIC = True
except ModuleNotFoundError:  # pragma: no cover - fallback when pydantic missing
    BaseModel = None  # type: ignore
    Field = field_validator = model_validator = None  # type: ignore
    _USE_PYDANTIC = False

PrivacyLevel = Literal["none", "minimal", "strict"]
HttpMethod = Literal["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

if _USE_PYDANTIC:
    # ------------------------------------------------------------------
    # Pydantic models (original implementations)
    # ------------------------------------------------------------------
    class EvidencePolicy(BaseModel):
        privacy_level: PrivacyLevel = Field(
            default="minimal",
            description="Controls PII redaction in snippets/headers: none|minimal|strict.",
        )

    class RequestPolicy(BaseModel):
        safe_methods_only: bool = Field(
            default=True,
            description="If true, only emit safe HTTP methods (GET/HEAD) in MVP.",
        )
        non_safe_methods: List[HttpMethod] = Field(
            default_factory=list,
            description="Additional HTTP methods to allow when safe_methods_only is false.",
        )
        max_rps: int = Field(default=2, ge=1, description="Maximum requests per second across all hosts.")
        concurrency: int = Field(default=4, ge=1, description="Maximum in-flight requests (global).")
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
        verify_tls: bool = Field(default=True, description="Verify TLS certificates for https requests.")
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
            return [str(s).strip() for s in v]

    class ScopeConfig(BaseModel):
        allowed: List[str] = Field(default_factory=list)
        base_urls: List[str] = Field(default_factory=list)
        denied: List[str] = Field(default_factory=list)
        path_policy: PathPolicy = Field(default_factory=PathPolicy)
        request_policy: RequestPolicy = Field(default_factory=RequestPolicy)
        timeouts: Timeouts = Field(default_factory=Timeouts)
        evidence: EvidencePolicy = Field(default_factory=EvidencePolicy)
        evidence_dir: str = "./evidence"

        @model_validator(mode="after")
        def _validate_scope(self) -> "ScopeConfig":
            if not self.allowed and not self.base_urls:
                raise ValueError(
                    "scope.yml must specify at least one of `allowed` hosts or `base_urls`."
                )
            return self

    class AuthScheme(BaseModel):
        audience: Optional[str] = None
        name: str
        type: str
        token: Optional[str] = None
        cookie: Optional[str] = None
        header: Optional[str] = None
        login_url: Optional[str] = None
        login_method: Optional[str] = None
        username: Optional[str] = None
        password: Optional[str] = None
        client_id: Optional[str] = None
        client_secret: Optional[str] = None
        token_url: Optional[str] = None
        refresh_token: Optional[str] = None
        grant_type: Optional[str] = None
        scope: Optional[str] = None
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
                        raise ValueError(
                            "oauth2 client_credentials requires client_id and client_secret"
                        )
                if self.grant_type == "password":
                    if not (
                        self.client_id
                        and self.client_secret
                        and self.username
                        and self.password
                    ):
                        raise ValueError(
                            "oauth2 password grant requires client_id, client_secret, username, password"
                        )
            elif t == "form_login":
                if not (
                    self.login_url
                    and self.username_field
                    and self.password_field
                    and self.username
                    and self.password
                ):
                    raise ValueError(
                        "form_login requires login_url, username_field, password_field, username, password"
                    )
            return self

    class AuthConfig(BaseModel):
        auth_schemes: List[AuthScheme] = Field(default_factory=list)

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
        generated_by: str = "amac"
        version: str = "0.1.0"
        endpoints: List[Endpoint] = Field(default_factory=list)
else:
    # ------------------------------------------------------------------
    # Lightweight dataclass fallbacks used when pydantic is unavailable
    # ------------------------------------------------------------------
    from dataclasses import dataclass, field

    @dataclass
    class EvidencePolicy:
        privacy_level: PrivacyLevel = "minimal"

    @dataclass
    class RequestPolicy:
        safe_methods_only: bool = True
        non_safe_methods: List[str] = field(default_factory=list)
        max_rps: int = 2
        concurrency: int = 4
        per_host_concurrency: int = 2
        global_jitter_ms: int = 60
        backoff_cap_s: float = 4.0
        allow_redirects: bool = False
        verify_tls: bool = True
        hard_request_budget: int = 0

    @dataclass
    class Timeouts:
        connect: int = 5
        read: int = 15

    @dataclass
    class PathPolicy:
        allow_paths: List[str] = field(default_factory=list)
        deny_paths: List[str] = field(default_factory=list)

    @dataclass
    class ScopeConfig:
        allowed: List[str] = field(default_factory=list)
        base_urls: List[str] = field(default_factory=list)
        denied: List[str] = field(default_factory=list)
        path_policy: PathPolicy = field(default_factory=PathPolicy)
        request_policy: RequestPolicy = field(default_factory=RequestPolicy)
        timeouts: Timeouts = field(default_factory=Timeouts)
        evidence: EvidencePolicy = field(default_factory=EvidencePolicy)
        evidence_dir: str = "./evidence"

    @dataclass
    class AuthScheme:
        name: str
        type: str
        token: Optional[str] = None
        cookie: Optional[str] = None
        header: Optional[str] = None
        login_url: Optional[str] = None
        username: Optional[str] = None
        password: Optional[str] = None
        client_id: Optional[str] = None
        client_secret: Optional[str] = None
        token_url: Optional[str] = None
        grant_type: Optional[str] = None
        scope: Optional[str] = None
        username_field: Optional[str] = None
        password_field: Optional[str] = None
        extra_fields: Dict[str, Any] = field(default_factory=dict)

    @dataclass
    class AuthConfig:
        auth_schemes: List[AuthScheme] = field(default_factory=list)

    @dataclass
    class Endpoint:
        method: HttpMethod
        url: str
        requires_auth: Optional[bool] = None
        template: Optional[str] = None
        source: Literal["openapi"] = "openapi"
        tags: List[str] = field(default_factory=list)
        operation_id: Optional[str] = None
        extra: Dict[str, Any] = field(default_factory=dict)

    @dataclass
    class EndpointSet:
        generated_by: str = "amac"
        version: str = "0.1.0"
        endpoints: List[Endpoint] = field(default_factory=list)
