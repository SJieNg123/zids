# src/client/io/token_http.py
from __future__ import annotations
import json
import base64
import urllib.request
from typing import Tuple

from src.client.online.ot_pad_oracle import TokenSource


class HTTPTokenSource(TokenSource):
    """
    Fetch OT tokens over HTTP(S).

    Server API expectation (adjust to your server):
      POST {base_url}/token  with JSON body:
        {"row_id": <int>, "x": <int>}
      Response JSON:
        {"token_b64": "<base64-bytes>"}  # exactly cmax*k' bytes after decoding

    You can adapt 'make_request' to match your wire format.
    """
    def __init__(self, base_url: str, timeout: float = 10.0, extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.extra_headers = extra_headers or {}

    def _post_json(self, path: str, obj: dict) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(obj).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in self.extra_headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            if resp.status // 100 != 2:
                raise RuntimeError(f"HTTP {resp.status}")
            payload = resp.read()
        try:
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"invalid JSON response: {e}")

    # --- TokenSource API ---
    def get_token(self, row_id: int, x: int) -> bytes:
        if not (0 <= x <= 255):
            raise ValueError("x must be a byte (0..255)")
        rsp = self._post_json("/token", {"row_id": int(row_id), "x": int(x)})
        if "token_b64" not in rsp:
            raise RuntimeError("server response missing 'token_b64'")
        try:
            token = base64.b64decode(rsp["token_b64"], validate=True)
        except Exception as e:
            raise RuntimeError(f"invalid base64 token: {e}")
        return token
