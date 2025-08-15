from __future__ import annotations

import asyncio
import base64
import hashlib
import random
import re
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from ..models import AuthScheme, PrivacyLevel, Timeouts

# -----------------------------
# Simple async rate limiter (tokens per 1s window)
# -----------------------------

class AsyncRateLimiter:
    """
    Allow up to `rate` acquisitions per rolling 1-second window.
    Implemented without external deps to keep footprint small.
    """
    def __init__(self, rate: int):
        self.rate = max(0, int(rate))
        self._dq: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return  # unlimited

        async with self._lock:
            now = time.monotonic()
            # drop timestamps older than 1s
            while self._dq and (now - self._dq[0]) >= 1.0:
                self._dq.popleft()

            if len(self._dq) < self.rate:
                self._dq.append(now)
                return

            # need to wait until the oldest timestamp is >1s ago
            wait_for = 1.0 - (now - self._dq[0])
            if wait_for > 0:
                await asyncio.sleep(wait_for)

            # after sleep, record this acquisition
            now2 = time.monotonic()
            while self._dq and (now2 - self._dq[0]) >= 1.0:
                self._dq.popleft()
            self._dq.append(now2)


# -----------------------------
# HTTP client with retries/throttle/jitter and per-host caps
# -----------------------------

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _default_timeout(t: Timeouts) -> httpx.Timeout:
    # Use read timeout for write/pool too.
    return httpx.Timeout(connect=t.connect, read=t.read, write=t.read, pool=t.read)


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in {"authorization", "proxy-authorization", "cookie"}:
            redacted[k] = "<redacted>"
            continue
        if lk in {"x-api-key", "api-key"} or lk.startswith("x-auth"):
            redacted[k] = "<redacted>"
            continue
        redacted[k] = v
    return redacted


def _auth_headers_for_scheme(s: AuthScheme) -> Dict[str, str]:
    t = s.type
    if t == "bearer":
        return {s.header or "Authorization": f"Bearer {s.token}"}
    if t == "header":
        return {s.header or "Authorization": s.token or ""}
    if t == "cookie":
        # handled below by merging into Cookie header
        return {}
    if t == "basic":
        # Prefer native client auth, but also build header in case we attach ourselves.
        user = s.username or ""
        pwd = s.password or ""
        token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    return {}


def _merge_cookies(cookie1: Optional[str], cookie2: Optional[str]) -> Optional[str]:
    if cookie1 and cookie2:
        # naive merge; in practice, last-wins per cookie key—good enough for MVP
        return f"{cookie1}; {cookie2}"
    return cookie1 or cookie2


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


class HttpClient:
    """
    Thin wrapper over httpx.AsyncClient with:
      - global concurrency control AND per-host concurrency caps
      - requests-per-second throttling
      - optional global jitter before sends
      - basic retries with backoff & jitter (with a cap)
      - optional auth header/cookie injection
      - hard request budget (global) to avoid over-scanning
      - TLS verification toggle and redirect policy
    """

    def __init__(
        self,
        timeouts: Timeouts,
        *,
        max_rps: int = 2,
        concurrency: int = 4,
        per_host_concurrency: int = 2,
        global_jitter_ms: int = 60,
        user_agent: str = "AMAC/0.1.0 (+https://example.com)",
        max_attempts: int = 3,
        backoff_base: float = 0.5,  # seconds
        backoff_cap_s: float = 4.0,  # cap for exponential backoff
        allow_redirects: bool = False,
        verify_tls: bool = True,
        hard_request_budget: int = 0,  # 0 = unlimited
        privacy_level: PrivacyLevel = "minimal",
    ):
        self.timeouts = timeouts
        self._limiter = AsyncRateLimiter(max_rps)
        self._sem_global = asyncio.Semaphore(concurrency if concurrency > 0 else 1000)
        self._sem_per_host: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(per_host_concurrency if per_host_concurrency > 0 else 1000)
        )
        self._client = httpx.AsyncClient(
            http2=True,
            timeout=_default_timeout(timeouts),
            headers={"User-Agent": user_agent},
            follow_redirects=allow_redirects,
            verify=verify_tls,
        )
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_base = backoff_base
        self.backoff_cap_s = backoff_cap_s
        self.jitter_ms = max(0, int(global_jitter_ms))
        self._budget = max(0, int(hard_request_budget))
        self._budget_lock = asyncio.Lock()
        self._requests_made = 0
        self.privacy_level: PrivacyLevel = privacy_level

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        auth_scheme: Optional[AuthScheme] = None,
        headers: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
        allow_redirects: Optional[bool] = None,  # override if needed
        json: Any | None = None,
    ) -> Dict[str, Any]:
        """
        Perform a single HTTP request with retries, throttle, concurrency limits, jitter, and budget checks.

        Returns a serializable snapshot containing request/response metadata or error info:
        {
          "request": { "method": "...", "url": "...", "headers": {...} },
          "response": {...} OR "error": {"type": "...", "message":"..."},
          "timings": { "elapsed_ms": 123.4, "attempts": 1 }
        }
        """
        # Budget gate
        if not await self._consume_budget():
            return self._error_snapshot(method, url, "budget_exceeded", "Hard request budget exhausted.", 0.0, 0)

        # Build headers and cookies
        hdrs: Dict[str, str] = {}
        if headers:
            hdrs.update(headers)

        # Inject auth
        cookies_hdr: Optional[str] = cookie
        if auth_scheme is not None:
            hdrs.update(_auth_headers_for_scheme(auth_scheme))
            if auth_scheme.type == "cookie":
                cookies_hdr = _merge_cookies(cookies_hdr, auth_scheme.cookie)

        if cookies_hdr:
            existing = hdrs.get("Cookie")
            hdrs["Cookie"] = _merge_cookies(existing, cookies_hdr) or ""

        # Per-host concurrency semaphore
        host = _host_of(url)
        sem_host = self._sem_per_host[host]

        attempts = 0
        start_ns = time.perf_counter_ns()
        last_exc: Optional[Exception] = None
        response: Optional[httpx.Response] = None

        async with self._sem_global, sem_host:
            while attempts < self.max_attempts:
                attempts += 1

                # Global jitter
                if self.jitter_ms:
                    await asyncio.sleep(random.uniform(0, self.jitter_ms / 1000.0))

                await self._limiter.acquire()

                try:
                    # For "basic" we prefer to rely on native httpx auth to avoid log leakage
                    native_auth = None
                    if auth_scheme and auth_scheme.type == "basic":
                        native_auth = (auth_scheme.username or "", auth_scheme.password or "")

                    response = await self._client.request(
                        method.upper(),
                        url,
                        headers=hdrs,
                        auth=native_auth,
                        follow_redirects=bool(allow_redirects) if allow_redirects is not None else self._client.follow_redirects,
                        json=json,
                    )
                    if response.status_code in RETRYABLE_STATUS and attempts < self.max_attempts:
                        await self._sleep_backoff(attempts)
                        continue
                    break  # success or final attempt
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    last_exc = e
                    if attempts < self.max_attempts:
                        await self._sleep_backoff(attempts)
                        continue
                    break

        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1e6

        if response is None:
            # All attempts failed with a transport error
            msg = str(last_exc) if last_exc else "request failed without response"
            return self._error_snapshot(method, url, "transport_error", msg, elapsed_ms, attempts)

        snap = await self._snapshot_response(method, url, hdrs, response, elapsed_ms, attempts, json)
        return snap

    async def _sleep_backoff(self, attempt: int) -> None:
        # Exponential backoff with jitter and cap
        base = min(self.backoff_cap_s, self.backoff_base * (2 ** (attempt - 1)))
        jitter = random.uniform(0, base * 0.2)
        await asyncio.sleep(base + jitter)

    async def _snapshot_response(
        self,
        method: str,
        url: str,
        req_headers: Dict[str, str],
        resp: httpx.Response,
        elapsed_ms: float,
        attempts: int,
        req_json: Any | None = None,
    ) -> Dict[str, Any]:
        # Take a conservative subset of headers
        resp_headers_subset = {}
        for key in ("content-type", "content-length", "server", "date", "cache-control", "location"):
            if key in resp.headers:
                resp_headers_subset[key] = resp.headers.get(key)

        # Read body (HEAD may have none)
        raw = b""
        try:
            raw = resp.content or b""
        except Exception:
            raw = b""

        size = len(raw)
        sha = hashlib.sha256(raw).hexdigest() if size else None
        snippet = ""
        json_keys: Optional[list[str]] = None

        # Try to sample as text safely
        if size:
            # cap to 4096 chars to prevent huge memory in snapshots
            try:
                snippet = raw.decode(resp.encoding or "utf-8", errors="replace")[:4096]
            except Exception:
                snippet = raw[:4096].decode("utf-8", errors="replace")

            # Privacy redaction on snippet
            snippet = _sanitize_snippet(snippet, self.privacy_level)

            # if JSON, collect top-level keys to help diffing later
            ctype = resp.headers.get("content-type", "")
            if "json" in ctype:
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        json_keys = sorted([str(k) for k in data.keys()])
                    elif isinstance(data, list) and data and isinstance(data[0], dict):
                        # peek keys from first item
                        json_keys = sorted([str(k) for k in data[0].keys()])
                except Exception:
                    json_keys = None

        snapshot = {
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": _redact_headers(req_headers),
            },
            "response": {
                "status": resp.status_code,
                "headers": resp_headers_subset,
                "body": {
                    "size": size,
                    "sha256": sha,
                    "snippet": snippet,
                    "json_keys": json_keys,
                },
            },
            "timings": {"elapsed_ms": elapsed_ms, "attempts": attempts},
        }
        if req_json is not None:
            snapshot["request"]["json"] = req_json
        return snapshot

    def _error_snapshot(
        self,
        method: str,
        url: str,
        err_type: str,
        message: str,
        elapsed_ms: float,
        attempts: int,
    ) -> Dict[str, Any]:
        return {
            "request": {"method": method.upper(), "url": url, "headers": {}},
            "error": {"type": err_type, "message": message},
            "timings": {"elapsed_ms": elapsed_ms, "attempts": attempts},
        }

    async def _consume_budget(self) -> bool:
        if self._budget == 0:
            return True
        async with self._budget_lock:
            if self._requests_made >= self._budget:
                return False
            self._requests_made += 1
            return True


# -----------------------------
# Privacy redaction
# -----------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
TOKENISH_RE = re.compile(r"\b([A-Za-z0-9_\-]{24,})\b")  # crude: long opaque strings
CREDITCARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _sanitize_snippet(text: str, level: PrivacyLevel) -> str:
    if level == "none":
        return text
    # minimal = mask common high-risk tokens/emails/cc/ssn
    masked = EMAIL_RE.sub("<email>", text)
    masked = SSN_RE.sub("<ssn>", masked)
    masked = CREDITCARD_RE.sub("<cc>", masked)
    masked = TOKENISH_RE.sub("<secret>", masked)
    if level == "strict":
        # Strip to first 512 chars and remove lines containing potential secrets hints
        masked = masked[:512]
        lines = []
        for ln in masked.splitlines():
            lower = ln.lower()
            if any(k in lower for k in ("secret", "token", "bearer ", "apikey", "api-key", "authorization")):
                lines.append("<redacted>")
            else:
                lines.append(ln)
        masked = "\n".join(lines)
    return masked
