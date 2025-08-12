from __future__ import annotations

import asyncio
from typing import Optional, Tuple

import httpx

from ..models import AuthScheme


class AuthFlowError(RuntimeError):
    pass


async def fetch_oauth2_token(s: AuthScheme, *, timeout: float = 15.0) -> str:
    """
    Supports:
      - client_credentials
      - password
    Returns the access_token string.
    """
    assert s.type == "oauth2", "scheme must be oauth2"
    assert s.token_url, "oauth2 token_url is required"

    data = {"grant_type": s.grant_type or "client_credentials"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if s.audience:
        data["audience"] = s.audience
    if s.scope:
        data["scope"] = s.scope

    auth = (s.client_id or "", s.client_secret or "")

    if s.grant_type == "password":
        data["username"] = s.username or ""
        data["password"] = s.password or ""

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(s.token_url, data=data, auth=auth, headers=headers)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise AuthFlowError(f"OAuth2 token request failed: {e}") from e

        js = resp.json()
        tok = js.get("access_token")
        if not tok:
            raise AuthFlowError("OAuth2 response missing access_token")
        # Optionally capture refresh_token if provided
        if js.get("refresh_token"):
            s.refresh_token = js["refresh_token"]
        return str(tok)


async def refresh_oauth2_token(s: AuthScheme, *, timeout: float = 15.0) -> Optional[str]:
    """
    Try a refresh_token grant if refresh_token is present.
    Returns new access_token or None if not possible.
    """
    if s.type != "oauth2" or not s.token_url or not s.refresh_token:
        return None

    data = {"grant_type": "refresh_token", "refresh_token": s.refresh_token}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth = (s.client_id or "", s.client_secret or "")

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(s.token_url, data=data, auth=auth, headers=headers)
        if resp.status_code >= 400:
            return None
        js = resp.json()
        tok = js.get("access_token")
        if tok:
            return str(tok)
    return None


async def perform_form_login(s: AuthScheme, *, timeout: float = 15.0) -> str:
    """
    Perform a simple form-based login to capture a Set-Cookie.
    Returns a Cookie header string.
    """
    assert s.type == "form_login", "scheme must be form_login"
    if not (s.login_url and s.username and s.password and s.username_field and s.password_field):
        raise AuthFlowError("form_login requires login_url/username/password and field names")

    payload = {s.username_field: s.username, s.password_field: s.password}
    if s.extra_fields:
        payload.update({k: str(v) for k, v in s.extra_fields.items()})

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.request(
            s.login_method or "POST",
            s.login_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        # Collect cookies from jar
        cookie_str = _cookiejar_to_header(client)
        if not cookie_str:
            # Try reading raw Set-Cookie (some servers require manual propagation)
            sc = resp.headers.get("set-cookie")
            if sc:
                cookie_str = _setcookie_to_cookie_header(sc)
        if not cookie_str:
            raise AuthFlowError("form_login: no cookies captured after login")
        return cookie_str


def _cookiejar_to_header(client: httpx.AsyncClient) -> str:
    # Convert cookie jar to "k=v; k2=v2"
    jar = client.cookies.jar
    pairs = []
    for c in jar:
        if not c.value or not c.name:
            continue
        pairs.append(f"{c.name}={c.value}")
    return "; ".join(pairs)


def _setcookie_to_cookie_header(set_cookie: str) -> str:
    # Very naive: keep only the first "name=value" per cookie
    cookies = []
    for part in set_cookie.split(","):
        kv = part.split(";", 1)[0].strip()
        if "=" in kv:
            cookies.append(kv)
    return "; ".join(cookies)
