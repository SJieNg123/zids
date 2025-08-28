# src/client/io/payload_reader.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Union, Literal, BinaryIO
import os
import sys

BytesLike = Union[bytes, bytearray]

# -------------------------
# Options
# -------------------------

AsciiCase = Literal["none", "lower", "upper"]

@dataclass(frozen=True)
class PayloadOptions:
    """
    All knobs are OFF by default to preserve raw 256-ary alphabet.
    - max_len: truncate to at most this many bytes (None = unlimited)
    - ascii_case: optional ASCII-only case normalization (A-Z<->a-z), non-ASCII untouched
    - strip_nulls: drop 0x00 bytes (default False)
    - filter_ascii_printable: keep only [9,10,13] + [0x20..0x7E] (default False)
    """
    max_len: Optional[int] = None
    ascii_case: AsciiCase = "none"
    strip_nulls: bool = False
    filter_ascii_printable: bool = False


# -------------------------
# Core utilities
# -------------------------

def _ascii_lower_table() -> bytes:
    tbl = bytearray(range(256))
    for c in range(0x41, 0x5B):  # 'A'..'Z'
        tbl[c] = c + 0x20
    return bytes(tbl)

def _ascii_upper_table() -> bytes:
    tbl = bytearray(range(256))
    for c in range(0x61, 0x7B):  # 'a'..'z'
        tbl[c] = c - 0x20
    return bytes(tbl)

_LOWER_TBL = _ascii_lower_table()
_UPPER_TBL = _ascii_upper_table()

def _apply_options(data: bytes, opt: PayloadOptions) -> bytes:
    b = data
    if opt.max_len is not None and len(b) > opt.max_len:
        b = b[: opt.max_len]

    if opt.ascii_case == "lower":
        b = b.translate(_LOWER_TBL)
    elif opt.ascii_case == "upper":
        b = b.translate(_UPPER_TBL)

    if opt.strip_nulls:
        b = b.replace(b"\x00", b"")

    if opt.filter_ascii_printable:
        # keep HT(0x09), LF(0x0A), CR(0x0D), and 0x20..0x7E
        allowed = set([9, 10, 13] + list(range(0x20, 0x7F)))
        b = bytes(ch for ch in b if ch in allowed)

    return b


# -------------------------
# Public API
# -------------------------

def from_bytes(data: BytesLike, *, options: PayloadOptions = PayloadOptions()) -> bytes:
    """Return data as-is (copy), optionally applying options."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("from_bytes expects bytes/bytearray")
    return _apply_options(bytes(data), options)

def from_text(text: str, *, encoding: str = "utf-8", errors: str = "strict",
              options: PayloadOptions = PayloadOptions()) -> bytes:
    """Encode a str to bytes, then apply options."""
    b = text.encode(encoding, errors=errors)
    return _apply_options(b, options)

def from_file(path: str, *, options: PayloadOptions = PayloadOptions(),
              chunk_size: int = 1 << 20) -> bytes:
    """
    Read a file in binary mode. If options.max_len is set, stop early.
    chunk_size is only used for streaming read; output is a single bytes object.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    want = options.max_len
    out = bytearray()
    with open(path, "rb") as f:
        while True:
            need = chunk_size if want is None else max(0, min(chunk_size, want - len(out)))
            if want is not None and need == 0:
                break
            chunk = f.read(need if need > 0 else chunk_size)
            if not chunk:
                break
            out.extend(chunk)
            if want is not None and len(out) >= want:
                break
    return _apply_options(bytes(out), options)

def from_stdin(*, options: PayloadOptions = PayloadOptions(),
               chunk_size: int = 1 << 20) -> bytes:
    """Read from sys.stdin.buffer fully (or up to max_len) and return bytes."""
    return _read_stream(sys.stdin.buffer, options=options, chunk_size=chunk_size)

def _read_stream(stream: BinaryIO, *, options: PayloadOptions, chunk_size: int) -> bytes:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    want = options.max_len
    out = bytearray()
    while True:
        need = chunk_size if want is None else max(0, min(chunk_size, want - len(out)))
        if want is not None and need == 0:
            break
        chunk = stream.read(need if need > 0 else chunk_size)
        if not chunk:
            break
        out.extend(chunk)
        if want is not None and len(out) >= want:
            break
    return _apply_options(bytes(out), options)

def iter_file_chunks(path: str, *, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    """Yield raw file bytes in fixed-size chunks (no options/normalization)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            yield buf

def sliding_windows(data: BytesLike, *, window: int, step: int = 1,
                    drop_last: bool = False) -> Iterator[bytes]:
    """
    Yield overlapping windows over 'data' (already-in-memory).
      - window: size of each slice (bytes)
      - step: slide amount (bytes)
      - drop_last: if False, the final partial window is yielded; else it is dropped
    """
    if window <= 0 or step <= 0:
        raise ValueError("window and step must be positive")
    b = bytes(data)
    n = len(b)
    i = 0
    while i < n:
        j = i + window
        if j <= n:
            yield b[i:j]
        elif not drop_last:
            yield b[i:n]
        else:
            break
        i += step


# -------------------------
# CLI (optional quick check)
# -------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Payload reader (raw 256-ary by default)")
    p.add_argument("path", nargs="?", help="file path to read; omit to read stdin")
    p.add_argument("--max", dest="max_len", type=int, default=None)
    p.add_argument("--lower", action="store_true", help="ASCII lower-case normalization")
    p.add_argument("--upper", action="store_true", help="ASCII upper-case normalization")
    p.add_argument("--strip-nulls", action="store_true")
    p.add_argument("--ascii-printable", action="store_true", help="filter to printable ASCII + CR/LF/TAB")
    args = p.parse_args()

    if args.lower and args.upper:
        p.error("Choose at most one of --lower/--upper")

    case: AsciiCase = "lower" if args.lower else ("upper" if args.upper else "none")
    opt = PayloadOptions(
        max_len=args.max_len,
        ascii_case=case,
        strip_nulls=args.strip_nulls,
        filter_ascii_printable=args.ascii_printable,
    )

    if args.path:
        data = from_file(args.path, options=opt)
    else:
        data = from_stdin(options=opt)

    # Write to stdout (binary-safe)
    sys.stdout.buffer.write(data)
