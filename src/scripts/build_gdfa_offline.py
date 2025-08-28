# src/common/scripts/build_gdfa_offline.py
from __future__ import annotations
import argparse
import json
import os
import sys
import gzip
import struct
import hashlib
from dataclasses import asdict
from typing import List, Dict, Any, Iterable, Optional

# ----- imports from your codebase -----
from src.common.odfa.matrix import ODFA, ODFARow, ODFAEdge
from src.common.odfa.params import SecurityParams, SparsityParams, make_packing
from src.server.offline.gdfa_builder import build_gdfa_stream, GDFAPublicHeader, GDFAStream
from src.common.crypto.prf import prf_msg

# ============================================================
# ODFA JSON schema loader
# ============================================================

def load_odfa_json(path: str) -> ODFA:
    """
    Expect a JSON object:
    {
      "num_states": int,
      "start_state": int,
      "accepting": {"<state>": attack_id, ...} | [] | {},
      "rows": [
        {"edges":[ {"group_id":int, "next_state":int, "attack_id":int}, ... ]},
        ...
      ]
    }
    attack_id default = 0 if omitted.
    """
    with open(path, "rb") as f:
        data = json.loads(f.read().decode("utf-8"))

    required = ("num_states", "start_state", "rows")
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"ODFA JSON missing fields: {missing}")

    num_states = int(data["num_states"])
    start_state = int(data["start_state"])

    accepting_raw = data.get("accepting", {})
    if isinstance(accepting_raw, dict):
        accepting = {int(k): int(v) for k, v in accepting_raw.items()}
    elif isinstance(accepting_raw, list):
        # allow list of [state, attack_id]
        accepting = {int(s): int(a) for s, a in accepting_raw}
    else:
        raise ValueError("accepting must be an object or a list")

    rows_json = data["rows"]
    if not isinstance(rows_json, list):
        raise ValueError("rows must be a list")
    if len(rows_json) != num_states:
        raise ValueError("rows length must equal num_states")

    rows: List[ODFARow] = []
    for i, rj in enumerate(rows_json):
        edges_json = rj.get("edges", [])
        if not isinstance(edges_json, list):
            raise ValueError(f"rows[{i}].edges must be a list")
        edges: List[ODFAEdge] = []
        for ej in edges_json:
            gid = int(ej.get("group_id", -1))
            ns  = int(ej["next_state"])
            aid = int(ej.get("attack_id", 0))
            edges.append(ODFAEdge(group_id=gid, next_state=ns, attack_id=aid))
        rows.append(ODFARow(edges=edges))

    return ODFA(num_states=num_states, start_state=start_state, accepting=accepting, rows=rows)


# ============================================================
# Output writers (two-file & container)
# ============================================================

def write_twofile(output_dir: str, pub: GDFAPublicHeader, rows: Iterable[bytes], *, gzip_header: bool = False) -> None:
    os.makedirs(output_dir, exist_ok=True)
    header_path = os.path.join(output_dir, "header.json" + (".gz" if gzip_header else ""))
    rows_path   = os.path.join(output_dir, "rows.bin")

    # Collect rows into a single bytes object for hashing and length check
    rows_list = list(rows)
    for i, r in enumerate(rows_list):
        if len(r) != pub.row_bytes:
            raise ValueError(f"row {i} length {len(r)} != row_bytes {pub.row_bytes}")
    rows_blob = b"".join(rows_list)
    expected = pub.num_states * pub.row_bytes
    if len(rows_blob) != expected:
        raise ValueError(f"rows total length {len(rows_blob)} != {expected}")

    # Prepare header (JSON) and rows SHA-256
    header_obj = {
        "alphabet_size": pub.alphabet_size,
        "outmax": pub.outmax,
        "cmax": pub.cmax,
        "num_states": pub.num_states,
        "start_row": pub.start_row,
        "permutation": pub.permutation,
        "cell_bytes": pub.cell_bytes,
        "row_bytes": pub.row_bytes,
        "aid_bits": pub.aid_bits,
        "rows_sha256": hashlib.sha256(rows_blob).hexdigest(),
    }
    header_bytes = json.dumps(header_obj, indent=2, sort_keys=True).encode("utf-8")

    # Write header
    if gzip_header:
        with gzip.open(header_path, "wb") as gz:
            gz.write(header_bytes)
    else:
        with open(header_path, "wb") as f:
            f.write(header_bytes)

    # Write rows.bin
    with open(rows_path, "wb") as f:
        f.write(rows_blob)

    print(f"[OK] Wrote {header_path}")
    print(f"[OK] Wrote {rows_path} ({len(rows_blob)} bytes)")


_MAGIC = b"ZIDSv1\0"

def write_container(container_path: str, pub: GDFAPublicHeader, rows: Iterable[bytes]) -> None:
    os.makedirs(os.path.dirname(container_path) or ".", exist_ok=True)

    rows_list = list(rows)
    for i, r in enumerate(rows_list):
        if len(r) != pub.row_bytes:
            raise ValueError(f"row {i} length {len(r)} != row_bytes {pub.row_bytes}")
    rows_blob = b"".join(rows_list)
    expected = pub.num_states * pub.row_bytes
    if len(rows_blob) != expected:
        raise ValueError(f"rows total length {len(rows_blob)} != {expected}")

    header_obj = {
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
    hdr_bytes = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
    body_hash = hashlib.sha256(rows_blob).digest()

    with open(container_path, "wb") as f:
        f.write(_MAGIC)
        f.write(struct.pack(">I", len(hdr_bytes)))
        f.write(hdr_bytes)
        f.write(rows_blob)
        f.write(body_hash)

    print(f"[OK] Wrote container {container_path} ({len(rows_blob)} bytes + header + sha256)")


# ============================================================
# Optional secrets dump (CAUTION)
# ============================================================

def write_secrets(output_dir: str, stream: GDFAStream, mode: str) -> None:
    """
    mode ∈ {"none","invperm","full"}.
    "invperm": dump only inverse permutation (useful for debugging).
    "full":    also dump pad_seeds (DANGEROUS in production).
    """
    if mode == "none":
        return
    os.makedirs(output_dir, exist_ok=True)
    obj: Dict[str, Any] = {
        "inv_permutation": stream.secrets.inv_permutation,
    }
    if mode == "full":
        obj["pad_seeds_hex"] = [[s.hex() for s in row] for row in stream.secrets.pad_seeds]
    path = os.path.join(output_dir, "secrets.json")
    with open(path, "wb") as f:
        f.write(json.dumps(obj, indent=2, sort_keys=True).encode("utf-8"))
    print(f"[OK] Wrote {path}  (WARNING: contains sensitive material)" if mode == "full" else f"[OK] Wrote {path}")


# ============================================================
# pad_seed_fn using master-key (deterministic option)
# ============================================================

def make_pad_seed_fn_from_master(master_key: bytes):
    """
    Return a pad_seed_fn(new_row, col, k_bytes) that derives seed deterministically:
        seed = PRF(master_key, b"OFFLINE|row="||I2OSP4(row)||b"|col="||I2OSP2(col), k_bytes)
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) == 0:
        raise ValueError("master_key must be non-empty bytes")

    def i2osp(x: int, L: int) -> bytes:
        if x < 0 or x >= (1 << (8 * L)):
            raise ValueError("i2osp out of range")
        return x.to_bytes(L, "big")

    def pad_seed_fn(row: int, col: int, k_bytes: int) -> bytes:
        info = b"OFFLINE|row=" + i2osp(row, 4) + b"|col=" + i2osp(col, 2)
        return prf_msg(master_key, info, k_bytes)

    return pad_seed_fn


# ============================================================
# CLI
# ============================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build GDFA rows from an ODFA JSON (offline packing)")
    p.add_argument("--odfa", required=True, help="Path to ODFA JSON")
    p.add_argument("--outdir", default="dist/gdfa", help="Output directory (for two-file outputs and secrets)")
    p.add_argument("--format", choices=["jsonbin", "container"], default="container",
                   help="Output format: 'jsonbin' (header.json + rows.bin) or 'container' (.gdfa)")

    # Parameters
    p.add_argument("--k", type=int, default=128, help="PRG/PRF security k (bits)")
    p.add_argument("--kprime", type=int, default=128, help="Group-key size k' (bits)")
    p.add_argument("--kappa", type=int, default=128, help="Base-OT security parameter κ (bits)")
    p.add_argument("--alphabet", type=int, default=256, help="Alphabet size (default 256)")
    p.add_argument("--outmax", type=int, required=True, help="Max out-degree per row (columns)")
    p.add_argument("--cmax", type=int, required=True, help="Max memberships per symbol for this row")
    p.add_argument("--aid-bits", type=int, default=16, help="Bits allocated for attack_id (default 16)")

    # Deterministic pad seeds (optional)
    p.add_argument("--master-key-hex", help="Hex key for deterministic pad seeds (optional)")

    # Two-file toggles
    p.add_argument("--gzip-header", action="store_true", help="GZip header.json if using jsonbin format")
    p.add_argument("--container-path", help="Explicit .gdfa output path (otherwise <outdir>/gdfa.gdfa)")

    # Secrets dump (optional)
    p.add_argument("--save-secrets", choices=["none", "invperm", "full"], default="none",
                   help="Optionally write secrets.json (CAUTION: 'full' exposes pad seeds)")

    return p.parse_args(argv)


def main(argv: List[str]) -> None:
    args = parse_args(argv)

    # 1) Load ODFA
    odfa = load_odfa_json(args.odfa)

    # 2) Params
    sec = SecurityParams(k_bits=args.k, kprime_bits=args.kprime, kappa=args.kappa, alphabet_size=args.alphabet)
    sp  = SparsityParams(outmax=args.outmax, cmax=args.cmax)
    # Quick sanity: will raise if ODFA exceeds outmax
    odfa.sanity_check(outmax=sp.outmax)

    # 3) Optional deterministic pad seeds via master key
    pad_seed_fn = None
    if args.master_key_hex:
        try:
            master = bytes.fromhex(args.master_key_hex)
        except ValueError as e:
            raise SystemExit(f"invalid --master-key-hex: {e}")
        pad_seed_fn = make_pad_seed_fn_from_master(master)

    # 4) Build GDFA stream
    stream: GDFAStream = build_gdfa_stream(
        odfa, sec, sp,
        aid_bits=args.aid_bits,
        pad_seed_fn=pad_seed_fn,
    )
    pub = stream.public
    rows_iter = list(stream.rows)  # materialize once for hashing/writing

    # 5) Write outputs
    if args.format == "jsonbin":
        write_twofile(args.outdir, pub, rows_iter, gzip_header=args.gzip_header)
    else:
        path = args.container_path or os.path.join(args.outdir, "gdfa.gdfa")
        write_container(path, pub, rows_iter)

    # 6) Optional secrets dump
    write_secrets(args.outdir, stream, args.save_secrets)

    # 7) Summary
    print("\nSummary:")
    print(f"  num_states  : {pub.num_states}")
    print(f"  outmax/cmax : {pub.outmax}/{pub.cmax}")
    print(f"  cell_bytes  : {pub.cell_bytes}")
    print(f"  row_bytes   : {pub.row_bytes}")
    print(f"  start_row   : {pub.start_row}")
    print(f"  permutation : len={len(pub.permutation)} (hidden in header)")
    if args.master_key_hex:
        print("  pad seeds   : deterministic (PRF over master key)")
    else:
        print("  pad seeds   : random (os.urandom)")
    print("Done.")

if __name__ == "__main__":
    main(sys.argv[1:])
