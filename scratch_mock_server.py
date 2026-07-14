"""Throwaway mock Riva Server for local validation of the link flow.

Implements the endpoints the local tool calls:
  POST /link          -> {pairing_token, code, approve_url}
  POST /link/redeem   -> {tenant_id, api_key, server_url}
  POST /tenants/<id>/agents   (auth) -> {ok}
  POST /tenants/<id>/status   (auth) -> {ok}
Auto-approves immediately. Logs everything it receives to stdout.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 9911
TENANT = "acme-eng"
API_KEY = "riva_sk_live_1234567890abcdef"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = self._read()
        auth = self.headers.get("Authorization", "")
        path = self.path.rstrip("/")
        print(f"\n>>> POST {self.path}")
        if auth:
            print(f"    Authorization: {auth}")
        print(f"    body: {json.dumps(body)[:500]}")

        if path == "/link":
            self._send(
                200,
                {
                    "pairing_token": "pair_tok_abcdef",
                    "code": "RIVA-7Q2X",
                    "approve_url": f"http://localhost:{PORT}/approve?code=RIVA-7Q2X",
                },
            )
        elif path == "/link/redeem":
            self._send(200, {"tenant_id": TENANT, "api_key": API_KEY, "server_url": f"http://localhost:{PORT}"})
        elif path.startswith("/tenants/") and path.endswith("/agents"):
            if auth != f"Bearer {API_KEY}":
                self._send(401, {"error": "unauthorized"})
                return
            print(f"    ✓ registered agent: {body.get('name')}")
            self._send(200, {"ok": True})
        elif path.startswith("/tenants/") and path.endswith("/status"):
            if auth != f"Bearer {API_KEY}":
                self._send(401, {"error": "unauthorized"})
                return
            print(f"    ✓ heartbeat: {len(body.get('agents', []))} agents, health={json.dumps(body.get('health'))}")
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})


if __name__ == "__main__":
    print(f"Mock Riva Server on http://localhost:{PORT}  (tenant={TENANT})")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
