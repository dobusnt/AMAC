#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST = os.getenv("MOCK_HOST", "127.0.0.1")
PORT = int(os.getenv("MOCK_PORT", "8008"))
DEMO_BEARER_TOKEN = os.getenv("DEMO_BEARER_TOKEN", "demo")  # set to match examples/auth.yml


def json_bytes(data: dict) -> bytes:
    return json.dumps(data).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "AMACMock/1.0"

    # --- Utilities ---------------------------------------------------------

    def _send_json(self, code: int, payload: dict, headers: dict | None = None) -> None:
        body = json_bytes(payload)
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, text: str = "", headers: dict | None = None) -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    # --- Routes ------------------------------------------------------------

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path
        if path == "/status":
            # 200 OK, no body
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        else:
            self.send_error(404, "Not Found")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/status":
            return self._send_text(200, "ok")

        if path == "/users/me":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and auth.split(" ", 1)[1] == DEMO_BEARER_TOKEN:
                return self._send_json(
                    200,
                    {
                        "id": "1",
                        "email": "user@example.com",
                        "name": "Alice",
                        "role": "user",
                    },
                )
            return self._send_json(
                401,
                {"error": "unauthorized", "detail": "Provide valid Bearer token"},
                headers={"WWW-Authenticate": 'Bearer realm="mock"'},
            )

        m = re.fullmatch(r"/users/([^/]+)", path)
        if m:
            user_id = m.group(1)
            return self._send_json(
                200,
                {"id": user_id, "name": f"User{user_id}"},
            )

        if path == "/search":
            q = qs.get("q", [None])[0]
            page = int(qs.get("page", ["1"])[0])
            if not q:
                return self._send_json(400, {"error": "missing_param", "param": "q"})
            items = [{"id": f"{page}-{i}", "name": f"{q}-result-{i}"} for i in range(1, 4)]
            return self._send_json(200, {"items": items})

        self.send_error(404, "Not Found")

    # Less noisy logs
    def log_message(self, fmt: str, *args) -> None:
        # Comment out to re-enable default logging
        pass


def main() -> None:
    addr = (HOST, PORT)
    httpd = ThreadingHTTPServer(addr, Handler)
    print(f"Mock API listening on http://{HOST}:{PORT}")
    print("Routes:")
    print("  HEAD /status")
    print("  GET  /status")
    print("  GET  /users/me        (requires Authorization: Bearer <token>, default 'demo')")
    print("  GET  /users/{id}")
    print("  GET  /search?q=<term>&page=<n>")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
