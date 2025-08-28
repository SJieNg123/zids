# tests/test_offline_gdfa.py
from __future__ import annotations
import os
from typing import Tuple, List

from src.common.odfa.params import SecurityParams, SparsityParams, make_packing
from src.server.offline.gdfa_builder import (
    ODFA, ODFARow, ODFAEdge,
    build_gdfa_stream, GDFAPublicHeader, GDFASecrets
)
from src.common.crypto.prg import G_bits

def banner(s: str): print("\n======== " + s + " ========")

def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b

def _derive_cell_format(pub: GDFAPublicHeader) -> Tuple[int,int,int,int]:
    """Return (cell_bits, ns_bits, aid_bits, pad_bits)."""
    cell_bits = pub.cell_bytes * 8
    ns_bits = max(1, (pub.num_states - 1).bit_length())
    aid_bits = pub.aid_bits
    if ns_bits + aid_bits > cell_bits:
        raise RuntimeError("cell_bits too small")
    pad_bits = cell_bits - (ns_bits + aid_bits)
    return cell_bits, ns_bits, aid_bits, pad_bits

def _unpack_cell(pt: bytes, ns_bits: int, aid_bits: int, pad_bits: int) -> Tuple[int,int]:
    v = int.from_bytes(pt, "big")
    v >>= pad_bits
    ns_mask = (1 << ns_bits) - 1
    aid_mask = (1 << aid_bits) - 1
    ns = (v >> aid_bits) & ns_mask
    aid = v & aid_mask
    return ns, aid

def build_tiny_odfa() -> ODFA:
    # 4 states, outmax will be 3
    rows = [
        ODFARow([ODFAEdge(group_id=0, next_state=1, attack_id=0),
                 ODFAEdge(group_id=1, next_state=2, attack_id=0)]),
        ODFARow([ODFAEdge(group_id=2, next_state=2, attack_id=7)]),
        ODFARow([ODFAEdge(group_id=0, next_state=3, attack_id=0)]),
        ODFARow([]),
    ]
    return ODFA(num_states=4, start_state=0, accepting={2:7}, rows=rows)

def main():
    banner("Build offline GDFA stream")
    odfa = build_tiny_odfa()
    sec  = SecurityParams(k_bits=128, kprime_bits=128, kappa=128, alphabet_size=256)
    sp   = SparsityParams(outmax=3, cmax=2)
    gdfa = build_gdfa_stream(odfa, sec, sp)

    pub: GDFAPublicHeader = gdfa.public
    secz: GDFASecrets = gdfa.secrets
    rows = list(gdfa.rows)

    # Basic size checks
    assert len(rows) == odfa.num_states
    assert all(len(r) == pub.row_bytes for r in rows)
    cell_bits, ns_bits, aid_bits, pad_bits = _derive_cell_format(pub)

    # Inverse permutation from secrets
    inv_perm = secz.inv_permutation
    # Map: new_row -> old_state
    perm = pub.permutation

    banner("Decrypt each cell and verify contents")
    for new_row, old_state in enumerate(perm):
        row_bytes = rows[new_row]
        # Rebuild padded edges (same order as builder: existing edges then dummies)
        orig_edges = odfa.rows[old_state].edges
        padded: List[ODFAEdge] = list(orig_edges)
        while len(padded) < pub.outmax:
            padded.append(ODFAEdge(group_id=-1, next_state=0, attack_id=0))

        for c, edge in enumerate(padded):
            start = c * pub.cell_bytes
            ct = row_bytes[start:start+pub.cell_bytes]
            seed = secz.pad_seeds[new_row][c]
            pad = G_bits(seed, cell_bits, label=b"PRG|GDFA|cell")
            pt = bytes(a ^ b for a, b in zip(ct, pad))
            ns_perm, aid = _unpack_cell(pt, ns_bits, aid_bits, pad_bits)

            # Expected PER(next_state)
            exp_ns_perm = inv_perm[edge.next_state]
            assert ns_perm == exp_ns_perm, f"row {new_row} col {c}: ns mismatch"
            assert aid == edge.attack_id, f"row {new_row} col {c}: aid mismatch"
    print("\n[OFFLINE] All checks passed ✔")

if __name__ == "__main__":
    main()
