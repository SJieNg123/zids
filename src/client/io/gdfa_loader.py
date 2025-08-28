# src/client/io/gdfa_loader.py
from __future__ import annotations
import io
import os
import json
import gzip
import struct
import hashlib
from typing import Iterable, Tuple, List, Optional

from src.server.offline.gdfa_builder import GDFAPublicHeader
from src.client.online.gdfa_evaluator import RowStore


# =========================
# Helpers
# =========================

_REQUIRED_FIELDS = [
    "alphabet_size", "outmax", "cmax", "num_states", "start_row",
    "permutation", "cell_bytes", "row_bytes", "aid_bits",
]

def _read_maybe_gz(path: str) -> bytes:
    with open(path, "rb") as f:
        head = f.read(2)
        f.seek(0)
        if head == b"\x1f\x8b":  # gzip magic
            with gzip.open(f, "rb") as gz:
                return gz.read()
        return f.read()

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _to_pub(d: dict) -> GDFAPublicHeader:
    missing = [k for k in _REQUIRED_FIELDS if k not in d]
    if missing:
        raise ValueError(f"GDFAPublicHeader missing fields: {missing}")
    # Basic shape checks
    if not isinstance(d["permutation"], list):
        raise ValueError("permutation must be a list")
    pub = GDFAPublicHeader(
        alphabet_size=int(d["alphabet_size"]),
        outmax=int(d["outmax"]),
        cmax=int(d["cmax"]),
        num_states=int(d["num_states"]),
        start_row=int(d["start_row"]),
        permutation=[int(x) for x in d["permutation"]],
        cell_bytes=int(d["cell_bytes"]),
        row_bytes=int(d["row_bytes"]),
        aid_bits=int(d["aid_bits"]),
    )
    # sanity
    if len(pub.permutation) != pub.num_states:
        raise ValueError("permutation length must equal num_states")
    if not (0 <= pub.start_row < pub.num_states):
        raise ValueError("start_row out of range")
    return pub


# =========================
# Public API (JSON + BIN)
# =========================

def load_gdfa_from_files(
    header_json_path: str,
    rows_bin_path: str,
    *,
    verify_sha256: bool = True
) -> Tuple[GDFAPublicHeader, RowStore]:
    """
    Load GDFA from two files:
      - header_json_path: UTF-8 JSON with fields of GDFAPublicHeader
        (optionally includes "rows_sha256": hex string of SHA-256 over rows.bin)
      - rows_bin_path: concatenation of num_states rows, each of row_bytes bytes

    Supports .gz for header_json (auto-detected by gzip magic).
    """
    header_bytes = _read_maybe_gz(header_json_path)
    try:
        meta = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"failed to parse header JSON: {e}")

    pub = _to_pub(meta)

    rows_bytes = _read_maybe_gz(rows_bin_path)
    expected = pub.num_states * pub.row_bytes
    if len(rows_bytes) != expected:
        raise ValueError(f"rows.bin length {len(rows_bytes)} != num_states*row_bytes {expected}")

    if verify_sha256 and "rows_sha256" in meta:
        h = _sha256(rows_bytes)
        if h != meta["rows_sha256"]:
            raise ValueError(f"rows_sha256 mismatch: got {h}, expect {meta['rows_sha256']}")

    # Split into per-row bytes and build RowStore
    rows: List[bytes] = []
    off = 0
    for _ in range(pub.num_states):
        rows.append(rows_bytes[off:off + pub.row_bytes])
        off += pub.row_bytes

    return pub, RowStore(pub, rows)


# =========================
# Public API (single-file container)
# =========================

_MAGIC = b"ZIDSv1\0"
# Layout:
#   0..7    : magic "ZIDSv1\0"
#   8..11   : header_len_be (uint32)
#   12..    : header_json (UTF-8, header_len bytes)
#   ...     : rows payload (num_states*row_bytes bytes)
#   ...     : rows_sha256 (32 bytes, raw)
def load_gdfa_container(path: str, *, verify_sha256: bool = True) -> Tuple[GDFAPublicHeader, RowStore]:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 12 or data[:8] != _MAGIC:
        raise ValueError("invalid container: bad magic or too short")

    header_len = struct.unpack(">I", data[8:12])[0]
    pos = 12
    end_hdr = pos + header_len
    if end_hdr + 32 > len(data):
        raise ValueError("invalid container: header_len out of range")

    try:
        meta = json.loads(data[pos:end_hdr].decode("utf-8"))
    except Exception as e:
        raise ValueError(f"invalid container header JSON: {e}")
    pub = _to_pub(meta)

    rows_len = pub.num_states * pub.row_bytes
    pos = end_hdr
    end_rows = pos + rows_len
    if end_rows + 32 > len(data):
        raise ValueError("invalid container: rows payload truncated")

    rows_payload = data[pos:end_rows]
    trailer_hash = data[end_rows:end_rows + 32]  # raw bytes
    if verify_sha256:
        if hashlib.sha256(rows_payload).digest() != trailer_hash:
            raise ValueError("container rows SHA-256 mismatch")

    # Build RowStore
    rows: List[bytes] = []
    off = 0
    for _ in range(pub.num_states):
        rows.append(rows_payload[off:off + pub.row_bytes])
        off += pub.row_bytes

    return pub, RowStore(pub, rows)


# =========================
# Writer (optional, for tests)
# =========================

def write_gdfa_container(path: str, pub: GDFAPublicHeader, rows: Iterable[bytes]) -> None:
    """Helper to pack a container on server or for tests."""
    rows_list = list(rows)
    if len(rows_list) != pub.num_states:
        raise ValueError("rows length must equal num_states")
    for i, r in enumerate(rows_list):
        if len(r) != pub.row_bytes:
            raise ValueError(f"row {i} length {len(r)} != row_bytes {pub.row_bytes}")
    header = {
        "alphabet_size": pub.alphabet_size,
        "outmax": pub.outmax,
        "cmax": pub.cmax,
        "num_states": pub.num_states,
        "start_row": pub.start_row,
        "permutation": pub.permutation,
        "cell_bytes": pub.cell_bytes,
        "row_bytes": pub.row_bytes,
        "aid_bits": pub.aid_bits,
    }
    hdr_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    body = b"".join(rows_list)
    h = hashlib.sha256(body).digest()
    with open(path, "wb") as f:
        f.write(_MAGIC)
        f.write(struct.pack(">I", len(hdr_bytes)))
        f.write(hdr_bytes)
        f.write(body)
        f.write(h)