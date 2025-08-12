from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, List, Set
from urllib.parse import urljoin, urlparse

import httpx

from ..config import is_url_in_scope
from ..models import ScopeConfig

# --- tiny HTML <a href> extractor (no external deps) ------------------------

class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() != "a":
            return
        for k, v in attrs:
            if k.lower() == "href" and isinstance(v, str):
                self.hrefs.append(v)


# --- public API -------------------------------------------------------------

@dataclass
class CrawlResult:
    seeds: List[str]
    pages_fetched: int
    urls: List[str]  # absolute, in-scope, deduped


async def lightweight_discover(
    base_urls: Iterable[str],
    scope: ScopeConfig,
    *,
    budget: int = 200,
    timeout: float = 10.0,
) -> CrawlResult:
    """
    Super-light discovery for read-only endpoints:
      - fetch /, /robots.txt, /sitemap.xml if present
      - parse <a href> links (same-host only)
      - expand relative links to absolute
      - keep only HTTP/HTTPS URLs within scope
    Returns a deduped list of absolute URLs (method unspecified; intended for GET/HEAD).
    """
    seeds: List[str] = []
    for b in base_urls:
        u = b.rstrip("/")
        seeds.extend([u + "/", u + "/robots.txt", u + "/sitemap.xml"])

    seen: Set[str] = set()
    out: Set[str] = set()
    fetched = 0

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, http2=True) as client:
        q: asyncio.Queue[str] = asyncio.Queue()
        for s in seeds:
            await q.put(s)
            seen.add(s)

        async def worker():
            nonlocal fetched
            while fetched < budget:
                try:
                    url = await asyncio.wait_for(q.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    return
                try:
                    r = await client.get(url, headers={"User-Agent": "AMAC-Crawler/0.1"})
                    fetched += 1
                except Exception:
                    continue

                ctype = r.headers.get("content-type", "")
                text = ""
                try:
                    text = r.text
                except Exception:
                    text = ""

                # Collect links from HTML
                if "html" in ctype and text:
                    p = _HrefParser()
                    try:
                        p.feed(text)
                    except Exception:
                        pass
                    for href in p.hrefs:
                        absu = _normalize_href(url, href)
                        if not absu:
                            continue
                        if not _same_host(url, absu):
                            continue
                        if not is_url_in_scope(absu, scope):
                            continue
                        if absu not in seen:
                            seen.add(absu)
                            out.add(absu)
                            # limited breadth-first
                            if fetched + q.qsize() < budget and absu not in _resource_blacklist:
                                await q.put(absu)

                # Parse robots for sitemaps
                if url.endswith("/robots.txt") and text:
                    for sm in _sitemaps_from_robots(text):
                        if sm not in seen:
                            seen.add(sm)
                            await q.put(sm)

                # Parse sitemap.xml URLs
                if url.endswith("/sitemap.xml") and text:
                    for loc in _urls_from_sitemap_xml(text):
                        # only same-host as the sitemap origin and in scope
                        if _same_host(url, loc) and is_url_in_scope(loc, scope):
                            out.add(loc)

                q.task_done()

        # spin a few workers
        workers = [asyncio.create_task(worker()) for _ in range(4)]
        await asyncio.gather(*workers, return_exceptions=True)

    # Keep only http/https and in-scope
    urls = sorted(u for u in out if u.startswith(("http://", "https://")) and is_url_in_scope(u, scope))
    return CrawlResult(seeds=seeds, pages_fetched=fetched, urls=urls)


# --- helpers ----------------------------------------------------------------

_resource_blacklist = {"/favicon.ico", "/robots.txt", "/sitemap.xml"}

def _same_host(src: str, dst: str) -> bool:
    return (urlparse(src).hostname or "").lower() == (urlparse(dst).hostname or "").lower()

def _normalize_href(base_url: str, href: str) -> str | None:
    if not href or href.startswith(("mailto:", "tel:", "javascript:")):
        return None
    try:
        return urljoin(base_url, href)
    except Exception:
        return None

_SITEMAP_RE = re.compile(r"(?mi)^\s*sitemap:\s*(\S+)\s*$")

def _sitemaps_from_robots(text: str) -> List[str]:
    return [m.group(1).strip() for m in _SITEMAP_RE.finditer(text or "")]

def _urls_from_sitemap_xml(text: str) -> List[str]:
    # very small parser: find <loc>...</loc>
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text or "", flags=re.I)
