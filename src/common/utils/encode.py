# common/utils/encode.py
from __future__ import annotations
import os
from typing import Iterable, List, Tuple

# =========================
# Byte/bit utilities
# =========================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))

def random_bytes(length: int) -> bytes:
    """Cryptographically strong random bytes."""
    if length < 0:
        raise ValueError("random_bytes: length must be non-negative")
    return os.urandom(length)

# =========================
# Fixed-length integer encodings
# =========================

def os2ip(b: bytes) -> int:
    """Octet String to Integer (big-endian)."""
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("os2ip: input must be bytes")
    return int.from_bytes(b, "big")

def i2osp(x: int, length: int) -> bytes:
    """
    Integer to Octet String (big-endian), fixed length.
    Raises if x cannot fit into `length` bytes.
    """
    if length < 0:
        raise ValueError("i2osp: length must be non-negative")
    if x < 0 or x >= (1 << (8 * length)):
        raise ValueError("i2osp: integer too large for the requested length")
    return int(x).to_bytes(length, "big")

def q_byte_len(q: int) -> int:
    """Return the minimum #bytes to encode values modulo q."""
    if not isinstance(q, int) or q <= 0:
        raise ValueError("q_byte_len: invalid modulus")
    return (q.bit_length() + 7) // 8

# =========================
# Bit list conversions
# =========================

def int_to_bitlist(n: int, num_bits: int, msb_first: bool = True) -> List[int]:
    """
    Convert integer n to a list of bits of length `num_bits`.
    Bits are 0/1 ints. msb_first=True -> [b_{num_bits-1}, ..., b_0].
    """
    if n < 0:
        raise ValueError("int_to_bitlist: n must be non-negative")
    if num_bits < 0:
        raise ValueError("int_to_bitlist: num_bits must be non-negative")
    if n >= (1 << num_bits):
        raise ValueError("int_to_bitlist: n does not fit into num_bits")
    if msb_first:
        return [(n >> (num_bits - 1 - i)) & 1 for i in range(num_bits)]
    else:
        return [(n >> i) & 1 for i in range(num_bits)]

def bitlist_to_int(bits: Iterable[int], msb_first: bool = True) -> int:
    """Inverse of int_to_bitlist."""
    v = 0
    if msb_first:
        for b in bits:
            v = (v << 1) | (1 if b else 0)
    else:
        shift = 0
        for b in bits:
            v |= ((1 if b else 0) << shift)
            shift += 1
    return v

# =========================
# Padding / length-prefix helpers
# =========================

def lpad_zeros(b: bytes, length: int) -> bytes:
    """Left-pad with zeros to exactly `length` bytes (raise if too long)."""
    if len(b) > length:
        raise ValueError("lpad_zeros: input longer than target length")
    return b.rjust(length, b"\x00")

def rpad_zeros(b: bytes, length: int) -> bytes:
    """Right-pad with zeros to exactly `length` bytes (raise if too long)."""
    if len(b) > length:
        raise ValueError("rpad_zeros: input longer than target length")
    return b.ljust(length, b"\x00")

def u32_to_bytes(n: int) -> bytes:
    """4-byte big-endian unsigned int (for length prefixes)."""
    if not (0 <= n < (1 << 32)):
        raise ValueError("u32_to_bytes: out of range")
    return n.to_bytes(4, "big")

def bytes_to_u32(b: bytes) -> int:
    """Parse a 4-byte big-endian unsigned int."""
    if len(b) != 4:
        raise ValueError("bytes_to_u32: need exactly 4 bytes")
    return int.from_bytes(b, "big")

def encode_len_prefix(m: bytes) -> bytes:
    """Return 4-byte length prefix || m."""
    return u32_to_bytes(len(m)) + m

def decode_len_prefix(buf: bytes) -> Tuple[bytes, bytes]:
    """
    Parse 4-byte length prefix and return (payload, rest).
    Raises if buffer is shorter than declared length.
    """
    if len(buf) < 4:
        raise ValueError("decode_len_prefix: buffer too short for length")
    L = bytes_to_u32(buf[:4])
    if len(buf) < 4 + L:
        raise ValueError("decode_len_prefix: buffer shorter than declared length")
    return buf[4:4+L], buf[4+L:]

# =========================
# Slicing / chunking helpers
# =========================

def chunk_exact(data: bytes, size: int) -> List[bytes]:
    """Split data into fixed-size chunks; require exact division."""
    if size <= 0:
        raise ValueError("chunk_exact: size must be positive")
    if len(data) % size != 0:
        raise ValueError("chunk_exact: data length not a multiple of chunk size")
    return [data[i:i+size] for i in range(0, len(data), size)]

def split_exact(data: bytes, lengths: Iterable[int]) -> List[bytes]:
    """Split data into segments with the given exact lengths."""
    out: List[bytes] = []
    pos = 0
    for L in lengths:
        if L < 0:
            raise ValueError("split_exact: negative length")
        if pos + L > len(data):
            raise ValueError("split_exact: buffer shorter than sum(lengths)")
        out.append(data[pos:pos+L])
        pos += L
    if pos != len(data):
        raise ValueError("split_exact: leftover bytes not consumed")
    return out

# =========================
# Backward-compat shims (optional)
# =========================

def bytes_to_int(b: bytes) -> int:
    """Compatibility alias for os2ip()."""
    return os2ip(b)

# pad_bytes() 的語義不明確（左/右？），保留但建議改用 lpad_zeros/rpad_zeros。
def pad_bytes(b: bytes, length: int) -> bytes:
    """Deprecated: right-pad with zeros to `length` (use rpad_zeros instead)."""
    return rpad_zeros(b, length)
