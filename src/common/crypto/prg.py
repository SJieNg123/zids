# common/crypto/prg.py
from __future__ import annotations
import hmac
import hashlib
from typing import Optional

from common.utils.encode import i2osp

_HASH = hashlib.sha256
_BLOCKLEN = _HASH().digest_size  # 32 bytes for SHA-256

def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, _HASH).digest()

def _prg_ctr(seed: bytes, out_len: int, *, label: bytes) -> bytes:
    """
    HMAC-SHA256-CTR: deterministically expand `seed` into `out_len` bytes.
    data = b"PRG|" + label + b"|ctr=" + I2OSP(i,4) + b"|len=" + I2OSP(out_len,4)
    block_i = HMAC(seed, data), i = 1,2,...
    output = block_1 || block_2 || ... (truncate to out_len)
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label must be bytes")
    if out_len < 0:
        raise ValueError("out_len must be non-negative")

    out = bytearray()
    i = 1
    while len(out) < out_len:
        data = b"PRG|" + bytes(label) + b"|ctr=" + i2osp(i, 4) + b"|len=" + i2osp(out_len, 4)
        out.extend(_hmac(seed, data))
        i += 1
    return bytes(out[:out_len])

def G_bytes(seed: bytes, out_len: int, *, label: bytes = b"ZIDS|PRG") -> bytes:
    """
    Expand to an exact number of BYTES. Use when all consumers speak in bytes.
    Typical ZIDS uses:
      - out_len = outmax * k_prime_bits // 8  (rounded up)
      - or out_len = k_bits // 8 for PAD cells
    """
    return _prg_ctr(seed, out_len, label=label)

def G_bits(seed: bytes, out_bits: int, *, label: bytes = b"ZIDS|PRG") -> bytes:
    """
    Expand to an exact number of BITS (MSB-first truncation on the last byte).
    Returns a byte string whose length is ceil(out_bits/8); the superfluous
    low-order bits in the last byte are zeroed to respect the bit-length.
    """
    if out_bits < 0:
        raise ValueError("out_bits must be non-negative")
    out_len = (out_bits + 7) // 8
    if out_len == 0:
        return b""
    buf = _prg_ctr(seed, out_len, label=label)
    r = out_bits & 7
    if r == 0:
        return buf
    # Keep the top r bits, zero the low (8 - r) bits of the last byte.
    mask = (0xFF << (8 - r)) & 0xFF
    return buf[:-1] + bytes([buf[-1] & mask])
