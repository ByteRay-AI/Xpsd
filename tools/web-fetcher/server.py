#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ByteRay Ltd.
"""Long-running web-fetcher service.

Launches a headless Chromium once at startup and keeps it warm, then serves
render requests over HTTP:

    GET  /healthz          -> "ok" once the browser is ready
    POST /render {"url"}   -> the page rendered to clean markdown (text only)

The page is fully rendered (JavaScript executed) and converted to markdown —
headings, paragraphs, lists, code blocks, tables, and links preserved;
navigation, scripts, styles, and images stripped. Images are dropped, not
embedded, so the output stays text-only.

Requests are served single-threaded, which matches Playwright's sync API
(one render at a time).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, NavigableString, Tag
from playwright.sync_api import TimeoutError as PWTimeout, sync_playwright

PAGE_LOAD_TIMEOUT_MS = 30_000
SETTLE_MS = 1_500

_browser = None  # set once in main()


class BlockedFetch(Exception):
    """A request or response touched a non-public address."""


def check_url_allowed(url: str) -> str | None:
    """Return an error string if the URL must not be fetched, else None.

    The URL comes from an LLM that reads untrusted web content, so a
    prompt-injected page could ask for internal services or cloud metadata.
    Only public http(s) hosts are allowed; every resolved address must be
    global (blocks 127.0.0.0/8, RFC1918, link-local 169.254.0.0/16 including
    the cloud metadata endpoint, and IPv6 equivalents).

    This check alone is not enough: redirects and DNS rebinding can steer the
    browser somewhere the checked URL never named. render() therefore also
    re-checks every request the browser makes (covers redirect targets) and
    verifies the actual remote address every response was served from
    (covers rebinding), discarding the page if anything non-public answered.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "url must start with http:// or https://"
    host = parts.hostname
    if not host:
        return "url has no host"
    try:
        infos = socket.getaddrinfo(host, parts.port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return f"cannot resolve host: {e}"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return f"host resolves to non-public address {ip}; refusing to fetch"
    return None


# ---------------------------------------------------------------------------
# HTML -> Markdown (text only, no images)
# ---------------------------------------------------------------------------

def html_to_markdown(soup: BeautifulSoup, base_url: str) -> str:
    for tag in soup.find_all(["nav", "footer", "script", "style", "noscript", "svg", "form"]):
        tag.decompose()
    for tag in soup.find_all(attrs={"class": re.compile(
        r"cookie|banner|popup|modal|sidebar|advertisement|ad-", re.I
    )}):
        tag.decompose()
    for tag in soup.find_all(attrs={"id": re.compile(
        r"cookie|banner|popup|modal|sidebar|advertisement", re.I
    )}):
        tag.decompose()

    lines: list[str] = []
    _convert(soup.body or soup, lines, base_url)
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _convert(el: Tag, lines: list[str], base_url: str) -> None:
    for child in el.children:
        if isinstance(child, NavigableString):
            text = child.strip()
            if text:
                lines.append(text)
            continue
        if not isinstance(child, Tag):
            continue
        tag = child.name

        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            text = child.get_text(strip=True)
            if text:
                lines += ["", f"{'#' * int(tag[1])} {text}", ""]
        elif tag == "p":
            text = child.get_text(strip=True)
            if text:
                lines += ["", text]
        elif tag in ("ul", "ol"):
            lines.append("")
            for i, li in enumerate(child.find_all("li", recursive=False), 1):
                prefix = f"{i}." if tag == "ol" else "-"
                lines.append(f"{prefix} {li.get_text(strip=True)}")
            lines.append("")
        elif tag == "pre":
            lines += ["", "```", child.get_text().rstrip(), "```", ""]
        elif tag == "code":
            code_text = child.get_text()
            if "\n" in code_text or len(code_text) > 80:
                lines += ["", "```", code_text.strip(), "```", ""]
            elif code_text.strip():
                lines.append(f"`{code_text.strip()}`")
        elif tag == "table":
            _convert_table(child, lines)
        elif tag == "blockquote":
            text = child.get_text(strip=True)
            if text:
                lines += [f"> {text}", ""]
        elif tag == "hr":
            lines += ["", "---", ""]
        elif tag == "a":
            href = child.get("href", "")
            text = child.get_text(strip=True)
            if text and href and not href.startswith("#"):
                lines.append(f"[{text}]({urljoin(base_url, href)})")
            elif text:
                lines.append(text)
        elif tag in ("strong", "b"):
            text = child.get_text(strip=True)
            if text:
                lines.append(f"**{text}**")
        elif tag in ("em", "i"):
            text = child.get_text(strip=True)
            if text:
                lines.append(f"*{text}*")
        elif tag == "br":
            lines.append("")
        elif tag in ("img", "picture", "figure", "video", "audio"):
            continue  # text-only: drop media
        elif tag in ("span", "label", "time", "cite", "abbr"):
            text = child.get_text(strip=True)
            if text:
                lines.append(text)
        else:
            _convert(child, lines, base_url)


def _convert_table(table: Tag, lines: list[str]) -> None:
    rows = []
    for tr in table.find_all("tr"):
        cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
        if cells:
            rows.append(cells)
    if not rows:
        return
    max_cols = max(len(r) for r in rows)
    for row in rows:
        row += [""] * (max_cols - len(row))
    lines.append("")
    lines.append("| " + " | ".join(rows[0]) + " |")
    lines.append("| " + " | ".join(["---"] * max_cols) + " |")
    for row in rows[1:]:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render(url: str) -> str:
    context = _browser.new_context(
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    )
    page = context.new_page()
    violations: list[str] = []

    # Re-check every request the browser makes, including redirect targets.
    def guard_route(route):
        req_url = route.request.url
        deny = check_url_allowed(req_url)
        if deny:
            if route.request.is_navigation_request():
                violations.append(f"{req_url}: {deny}")
            route.abort("accessdenied")
        else:
            route.continue_()

    # Verify the actual remote address of each response (DNS rebinding).
    def guard_response(response):
        try:
            addr = response.server_addr()
        except Exception:
            return
        if not addr:
            return
        try:
            ip = ipaddress.ip_address(addr["ipAddress"])
        except ValueError:
            return
        if not ip.is_global:
            violations.append(f"{response.url}: served from non-public address {ip}")

    context.route("**/*", guard_route)
    page.on("response", guard_response)
    try:
        try:
            page.goto(url, wait_until="load", timeout=PAGE_LOAD_TIMEOUT_MS)
        except PWTimeout:
            pass
        page.wait_for_timeout(SETTLE_MS)
        html = page.content()
    finally:
        context.close()

    if violations:
        raise BlockedFetch("; ".join(violations[:3]))

    soup = BeautifulSoup(html, "html.parser")
    title = ""
    if soup.find("h1"):
        title = soup.find("h1").get_text(strip=True)
    if not title and soup.find("title"):
        title = soup.find("title").get_text(strip=True)
    header = f"# {title or url}\n\n**Source:** {url}\n\n---\n\n"
    return header + html_to_markdown(soup, url)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _send(self, code: int, body: str, ctype: str = "text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/healthz":
            self._send(200, "ok")
        else:
            self._send(404, "not found")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/render":
            self._send(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or "{}")
            url = (payload.get("url") or "").strip()
            deny = check_url_allowed(url)
            if deny:
                self._send(400, deny)
                return
            self._send(200, render(url), "text/markdown; charset=utf-8")
        except BlockedFetch as e:
            self._send(400, f"fetch blocked: {e}")
        except Exception as e:  # noqa: BLE001
            self._send(500, f"render error: {e}")


def main() -> None:
    global _browser
    pw = sync_playwright().start()
    _browser = pw.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
    )
    # Loopback only.
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
