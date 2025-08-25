# common/utils/checks.py
from __future__ import annotations
from typing import Iterable, Sequence

# ---------- basic type/length checks ----------

def ensure_bytes(x: bytes, *, name: str = "value") -> None:
    if not isinstance(x, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")

def ensure_bytes_fixed(x: bytes, length: int, *, name: str = "value") -> None:
    ensure_bytes(x, name=name)
    if len(x) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")

def ensure_bytes_nonempty(x: bytes, *, name: str = "value") -> None:
    ensure_bytes(x, name=name)
    if len(x) == 0:
        raise ValueError(f"{name} must be non-empty bytes")

def ensure_equal_length(items: Sequence[bytes], *, name: str = "items") -> int:
    if len(items) == 0:
        raise ValueError(f"{name} must be non-empty")
    L = len(items[0])
    for i, b in enumerate(items):
        ensure_bytes(b, name=f"{name}[{i}]")
        if len(b) != L:
            raise ValueError(f"{name}[{i}] length {len(b)} != {L}")
    return L

# ---------- integers / ranges ----------

def ensure_int(x: int, *, name: str = "value") -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")

def ensure_in_range(x: int, low: int, high: int, *, name: str = "value") -> None:
    """
    Ensure low <= x <= high (inclusive bounds).
    """
    ensure_int(x, name=name)
    if x < low or x > high:
        raise ValueError(f"{name} must be in [{low}, {high}]")

def ensure_index(x: int, size: int, *, name: str = "index") -> None:
    """
    Ensure 0 <= x < size.
    """
    ensure_int(x, name=name)
    if not (0 <= x < size):
        raise ValueError(f"{name} out of range: 0 <= {name} < {size}")

def ensure_bit(x: int, *, name: str = "bit") -> None:
    ensure_int(x, name=name)
    if x not in (0, 1):
        raise ValueError(f"{name} must be 0 or 1")

# ---------- group / field checks (Z_q) ----------

def ensure_mod_q(x: int, q: int, *, name: str = "value") -> None:
    ensure_int(x, name=name)
    ensure_int(q, name="q")
    if q <= 1:
        raise ValueError("q must be > 1")
    if not (0 <= x < q):
        raise ValueError(f"{name} must be in [0, q-1]")

def ensure_in_Zq_star(x: int, q: int, *, name: str = "value") -> None:
    """
    For prime q, Z_q^* = {1..q-1}.
    """
    ensure_mod_q(x, q, name=name)
    if x == 0:
        raise ValueError(f"{name} must be in Z_q^* (1..q-1)")

def ensure_subgroup_elem(y: int, p: int, q: int, *, name: str = "elem") -> None:
    """
    Quick check: y in <g> (prime-order subgroup) iff y^q ≡ 1 mod p and y != 0.
    """
    ensure_int(y, name=name)
    ensure_int(p, name="p")
    ensure_int(q, name="q")
    if not (1 < y < p):
        raise ValueError(f"{name} out of Z_p^* range")
    if pow(y, q, p) != 1:
        raise ValueError(f"{name} not in the prime-order subgroup (y^q != 1 mod p)")

# ---------- tables / collections ----------

def ensure_table_len(tbl: Sequence, expected: int, *, name: str = "table") -> None:
    if len(tbl) != expected:
        raise ValueError(f"{name} must have length {expected}, got {len(tbl)}")

def ensure_fixed_bytes_table(tbl: Sequence[bytes], expected: int, *, name: str = "table") -> int:
    ensure_table_len(tbl, expected, name=name)
    return ensure_equal_length(tbl, name=name)
