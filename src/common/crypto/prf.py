# src/common/crypto/prf.py
# from ddh_ot

from __future__ import annotations
import hmac, hashlib, struct

_BLOCK = 32  # SHA-256 output size

def _hkdf_expand(prk: bytes, info: bytes, out_len: int) -> bytes:
    """
    Simple HKDF-Expand style expander using HMAC-SHA256.
    Not exposed; used to build counter-mode PRF with domain separation.
    """
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    if out_len == 0:
        return b""
    okm = bytearray()
    counter = 1
    t = b""
    while len(okm) < out_len:
        # T(n) = HMAC-PRK(T(n-1) || info || counter)
        t = hmac.new(prk, t + info + struct.pack(">I", counter), hashlib.sha256).digest()
        okm += t
        counter += 1
    return bytes(okm[:out_len])

def prf_msg(key: bytes, info: bytes, out_len: int) -> bytes:
    """
    PRF(key, info, out_len): HMAC-SHA256 with counter expansion.
    * key: secret key material (bytes)
    * info: domain-separation/context bytes (label, indexes, salts, etc.)
    * out_len: number of bytes desired
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise TypeError("key must be non-empty bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise TypeError("info must be bytes")
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    # For our use we treat `key` directly as PRK (already secret, fixed-length is fine)
    return _hkdf_expand(bytes(key), bytes(info), out_len)

def prf_labeled(key: bytes, label: bytes, out_len: int) -> bytes:
    """
    Convenience wrapper: PRF with a label only.
    Equivalent to prf_msg(key, b\"PRF|\"+label, out_len).
    """
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label must be bytes")
    return prf_msg(key, b"PRF|" + bytes(label), out_len)