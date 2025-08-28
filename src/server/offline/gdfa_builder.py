# src/server/offline/gdfa_builder.py
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional, Callable

from src.common.odfa.params import SecurityParams, SparsityParams, PackingParams, make_packing
from src.common.odfa.matrix import ODFA, ODFARow, ODFAEdge, pad_row_to_outmax
from src.common.odfa.packing import CellFormat, plan_cell_format
from src.common.odfa.permutation import sample_perm, inverse_perm
from src.common.crypto.prg import G_bits


# =========================
# Bytes packing for a cell
# =========================

def _pack_bits(ns: int, aid: int, fmt: CellFormat) -> bytes:
    """
    Pack PER(next_state) and attack_id into MSB-first bitstring of fmt.total_bits,
    then to bytes. Padding bits are zero.
    """
    if ns < 0 or ns >= (1 << fmt.ns_bits):
        raise ValueError("next_state index out of range for ns_bits")
    if aid < 0 or aid >= (1 << fmt.aid_bits):
        raise ValueError("attack_id out of range for aid_bits")
    v = ((ns << fmt.aid_bits) | aid) << fmt.pad_bits
    return v.to_bytes(fmt.total_bytes, "big")


# =========================
# Outputs (public header / secrets / stream)
# =========================

@dataclass
class GDFAPublicHeader:
    """
    Public metadata the client needs to parse GDFA rows.
    """
    alphabet_size: int
    outmax: int
    cmax: int
    num_states: int
    start_row: int          # PER(start_state)
    permutation: List[int]  # PER: new_row_id -> old_state_id
    cell_bytes: int         # bytes per cell
    row_bytes: int          # bytes per row (= outmax * cell_bytes)
    aid_bits: int


@dataclass
class GDFASecrets:
    """
    Server-only secrets:
      - pad_seeds[new_row][col] : k-byte seed for PRG pad expansion
      - inv_permutation         : old_state -> new_row
    """
    pad_seeds: List[List[bytes]]
    inv_permutation: List[int]


@dataclass
class GDFAStream:
    """
    Offline product:
      - public: header with sizes and permutation
      - secrets: server-only materials
      - rows: iterator yielding encrypted rows in PER order
    """
    public: GDFAPublicHeader
    secrets: GDFASecrets
    rows: Iterable[bytes]  # yields row_bytes per row in PER order


# =========================
# Builder
# =========================

def build_gdfa_stream(
    odfa: ODFA,
    sec: SecurityParams,
    sp: SparsityParams,
    *,
    aid_bits: int = 16,
    # Optional: integrate your online GK→seed rule here so offline rows match online tokens.
    # Signature: pad_seed_fn(new_row: int, col: int, k_bytes: int) -> bytes (length == k_bytes)
    pad_seed_fn: Optional[Callable[[int, int, int], bytes]] = None,
) -> GDFAStream:
    """
    Build a GDFA as a row-stream, reusing common ODFA types, packing, and permutation helpers.

    NOTE (integration with online OT):
      If you want the client to decrypt using GK tokens, pass pad_seed_fn implementing:
        seed = PRF(GK[row][col], b"ZIDS|SEED|row="||I2OSP(row,4)||b"|col="||I2OSP(col,2), k_bytes)
      Then pad = PRG(seed, gdfa_cell_pad_bits, label="PRG|GDFA|cell").
      The same rule must be used by the client oracle.
    """
    # 1) Packing params and sanity checks
    pack: PackingParams = make_packing(sec, sp)
    odfa.sanity_check(outmax=sp.outmax)

    # 2) Decide cell layout
    fmt: CellFormat = plan_cell_format(num_states=odfa.num_states, pack=pack, aid_bits=aid_bits)
    assert fmt.total_bits == pack.gdfa_cell_pad_bits, "packing mismatch"
    cell_bytes = fmt.total_bytes
    row_bytes = sp.outmax * cell_bytes

    # 3) Permutation (PER) and its inverse
    perm = sample_perm(odfa.num_states)           # new_row -> old_state
    inv_perm = inverse_perm(perm)                 # old_state -> new_row
    start_row = inv_perm[odfa.start_state]

    # 4) Pre-sample per-cell seeds (server-only)
    pad_seeds: List[List[bytes]] = []
    for new_row in range(odfa.num_states):
        row_seeds: List[bytes] = []
        for c in range(sp.outmax):
            if pad_seed_fn is None:
                seed = os.urandom(sec.k_bytes)
            else:
                seed = pad_seed_fn(new_row, c, sec.k_bytes)
                if not isinstance(seed, (bytes, bytearray)) or len(seed) != sec.k_bytes:
                    raise ValueError("pad_seed_fn must return bytes of length k_bytes")
            row_seeds.append(bytes(seed))
        pad_seeds.append(row_seeds)

    public = GDFAPublicHeader(
        alphabet_size=sec.alphabet_size,
        outmax=sp.outmax,
        cmax=sp.cmax,
        num_states=odfa.num_states,
        start_row=start_row,
        permutation=perm,
        cell_bytes=cell_bytes,
        row_bytes=row_bytes,
        aid_bits=aid_bits,
    )
    secrets = GDFASecrets(pad_seeds=pad_seeds, inv_permutation=inv_perm)

    # 5) Row generator in PER order
    def _row_iter() -> Iterable[bytes]:
        for new_row, old_state in enumerate(perm):
            # pad row to outmax using common helper (dummy edges are: group_id=-1, next_state=0, attack_id=0)
            base_row: ODFARow = odfa.rows[old_state]
            padded: ODFARow = pad_row_to_outmax(base_row, outmax=sp.outmax)

            cells_enc: List[bytes] = []
            for c, edge in enumerate(padded.edges):
                ns_perm = inv_perm[edge.next_state]          # map target state to its PER row id
                pt = _pack_bits(ns_perm, edge.attack_id, fmt)  # fixed-length plaintext cell
                seed = secrets.pad_seeds[new_row][c]
                pad = G_bits(seed, pack.gdfa_cell_pad_bits, label=b"PRG|GDFA|cell")
                ct = bytes(a ^ b for a, b in zip(pt, pad))
                cells_enc.append(ct)

            row_bytes_buf = b"".join(cells_enc)
            assert len(row_bytes_buf) == row_bytes
            yield row_bytes_buf

    return GDFAStream(public=public, secrets=secrets, rows=_row_iter())