# src/common/net/messages.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List
import base64

# =========================
# Protocol constants
# =========================

PROTO_VERSION = "1.0"
MEDIA_TYPE_JSON = "application/zids+json;v=1"

# Canonical endpoints (may be used by client/server routers)
ENDPOINT_TOKEN = "/token"
ENDPOINT_HEALTH = "/health"
ENDPOINT_GDFA_INFO = "/gdfa/info"

__all__ = [
    "PROTO_VERSION", "MEDIA_TYPE_JSON",
    "ENDPOINT_TOKEN", "ENDPOINT_HEALTH", "ENDPOINT_GDFA_INFO",
    "TokenRequest", "TokenResponse",
    "ErrorResponse", "HealthResponse", "GDFAInfoResponse",
    "b64encode_bytes", "b64decode_bytes",
]


# =========================
# Helpers
# =========================

def b64encode_bytes(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("b64encode_bytes expects bytes")
    return base64.b64encode(bytes(data)).decode("ascii")

def b64decode_bytes(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("b64decode_bytes expects str")
    return base64.b64decode(s.encode("ascii"), validate=True)

def _require_fields(obj: Dict[str, Any], fields: Tuple[str, ...]) -> None:
    missing = [k for k in fields if k not in obj]
    if missing:
        raise ValueError(f"missing required field(s): {missing}")

def _ensure_uint(name: str, x: Any) -> int:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x < 0:
        raise ValueError(f"{name} must be >= 0")
    return x


# =========================
# /token  (row_id, x) -> token
# =========================

@dataclass(frozen=True)
class TokenRequest:
    """
    Request body for POST /token

    Fields:
      - row_id: int in [0, num_states)
      - x: byte value in [0,255]
      - sid: optional opaque session identifier (for server-side auditing / rate limiting)
    """
    row_id: int
    x: int
    sid: Optional[str] = None

    def sanity_check(self, *, num_states: Optional[int] = None) -> None:
        _ensure_uint("row_id", self.row_id)
        _ensure_uint("x", self.x)
        if self.x > 255:
            raise ValueError("x must be in [0,255]")
        if num_states is not None and not (0 <= self.row_id < num_states):
            raise ValueError("row_id out of range for current GDFA")

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"row_id": int(self.row_id), "x": int(self.x)}
        if self.sid is not None:
            d["sid"] = str(self.sid)
        return d

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "TokenRequest":
        _require_fields(obj, ("row_id", "x"))
        row_id = _ensure_uint("row_id", obj["row_id"])
        x = _ensure_uint("x", obj["x"])
        sid = obj.get("sid")
        if sid is not None and not isinstance(sid, str):
            raise TypeError("sid must be str if provided")
        return TokenRequest(row_id=row_id, x=x, sid=sid)


@dataclass(frozen=True)
class TokenResponse:
    """
    Response body for POST /token

    Fields:
      - token_b64: base64 of token bytes (exact length must be cmax * kprime_bytes)
      - ver: optional protocol version (string)
    """
    token: bytes
    ver: str = PROTO_VERSION

    def to_json(self) -> Dict[str, Any]:
        return {
            "token_b64": b64encode_bytes(self.token),
            "ver": self.ver,
        }

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "TokenResponse":
        _require_fields(obj, ("token_b64",))
        token = b64decode_bytes(obj["token_b64"])
        ver = obj.get("ver", PROTO_VERSION)
        if not isinstance(ver, str):
            raise TypeError("ver must be str")
        return TokenResponse(token=token, ver=ver)

    def assert_length(self, expected_len: int) -> None:
        if len(self.token) != expected_len:
            raise ValueError(f"token length mismatch: got {len(self.token)}, expect {expected_len}")


# =========================
# Error response (generic)
# =========================

# Canonical error codes
ERR_BAD_REQUEST       = "bad_request"
ERR_UNAUTHORIZED      = "unauthorized"
ERR_FORBIDDEN         = "forbidden"
ERR_NOT_FOUND         = "not_found"
ERR_RATE_LIMITED      = "rate_limited"
ERR_VERSION_MISMATCH  = "version_mismatch"
ERR_INVALID_ROW       = "invalid_row"
ERR_INVALID_SYMBOL    = "invalid_symbol"
ERR_LENGTH_MISMATCH   = "length_mismatch"
ERR_SERVER_ERROR      = "server_error"

@dataclass(frozen=True)
class ErrorResponse:
    """
    Uniform error envelope.

    Fields:
      - error: canonical code (see constants above)
      - message: human-readable explanation
      - details: optional structured payload (dict)
      - ver: protocol version (string)
    """
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    ver: str = PROTO_VERSION

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"error": self.error, "message": self.message, "ver": self.ver}
        if self.details is not None:
            d["details"] = self.details
        return d

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "ErrorResponse":
        _require_fields(obj, ("error", "message"))
        error = obj["error"]
        message = obj["message"]
        if not isinstance(error, str) or not isinstance(message, str):
            raise TypeError("error and message must be strings")
        details = obj.get("details")
        if details is not None and not isinstance(details, dict):
            raise TypeError("details must be an object if provided")
        ver = obj.get("ver", PROTO_VERSION)
        if not isinstance(ver, str):
            raise TypeError("ver must be str")
        return ErrorResponse(error=error, message=message, details=details, ver=ver)


# =========================
# /health
# =========================

@dataclass(frozen=True)
class HealthResponse:
    """
    Lightweight health endpoint response.
    """
    status: str = "ok"
    ver: str = PROTO_VERSION
    server: Optional[str] = None  # optional identifier

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"status": self.status, "ver": self.ver}
        if self.server is not None:
            d["server"] = self.server
        return d

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "HealthResponse":
        status = obj.get("status", "ok")
        ver = obj.get("ver", PROTO_VERSION)
        server = obj.get("server")
        if not isinstance(status, str) or not isinstance(ver, str):
            raise TypeError("status/ver must be str")
        if server is not None and not isinstance(server, str):
            raise TypeError("server must be str if provided")
        return HealthResponse(status=status, ver=ver, server=server)


# =========================
# /gdfa/info   (mirror of GDFAPublicHeader)
# =========================

@dataclass(frozen=True)
class GDFAInfoResponse:
    """
    Mirrors server.offline.gdfa_builder.GDFAPublicHeader for client bootstrap over HTTP.

    Fields:
      - alphabet_size, outmax, cmax, num_states, start_row, permutation, cell_bytes, row_bytes, aid_bits
      - ver: protocol version
    """
    alphabet_size: int
    outmax: int
    cmax: int
    num_states: int
    start_row: int
    permutation: List[int]
    cell_bytes: int
    row_bytes: int
    aid_bits: int
    ver: str = PROTO_VERSION

    def to_json(self) -> Dict[str, Any]:
        return {
            "alphabet_size": int(self.alphabet_size),
            "outmax": int(self.outmax),
            "cmax": int(self.cmax),
            "num_states": int(self.num_states),
            "start_row": int(self.start_row),
            "permutation": [int(x) for x in self.permutation],
            "cell_bytes": int(self.cell_bytes),
            "row_bytes": int(self.row_bytes),
            "aid_bits": int(self.aid_bits),
            "ver": self.ver,
        }

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "GDFAInfoResponse":
        required = (
            "alphabet_size", "outmax", "cmax", "num_states", "start_row",
            "permutation", "cell_bytes", "row_bytes", "aid_bits"
        )
        _require_fields(obj, required)
        perm = obj["permutation"]
        if not isinstance(perm, list) or not all(isinstance(x, int) for x in perm):
            raise TypeError("permutation must be a list[int]")
        return GDFAInfoResponse(
            alphabet_size=int(obj["alphabet_size"]),
            outmax=int(obj["outmax"]),
            cmax=int(obj["cmax"]),
            num_states=int(obj["num_states"]),
            start_row=int(obj["start_row"]),
            permutation=[int(x) for x in perm],
            cell_bytes=int(obj["cell_bytes"]),
            row_bytes=int(obj["row_bytes"]),
            aid_bits=int(obj["aid_bits"]),
            ver=str(obj.get("ver", PROTO_VERSION)),
        )