# tests/test_online_eval.py
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Tuple, List

from src.client.online.gdfa_evaluator import RowStore, GDFARunner, PadOracle, EvalResult
from src.server.offline.gdfa_builder import GDFAPublicHeader

def banner(s: str): print("\n======== " + s + " ========")

def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b

def _pack_cell(ns: int, aid: int, ns_bits: int, aid_bits: int, pad_bits: int, cell_bytes: int) -> bytes:
    if ns >= (1 << ns_bits) or aid >= (1 << aid_bits):
        raise ValueError("ns/aid out of range")
    v = ((ns << aid_bits) | aid) << pad_bits
    return v.to_bytes(cell_bytes, "big")

@dataclass
class FakeOracle(PadOracle):
    """Return (col, pad) from preloaded pads using a deterministic rule: col = x % outmax."""
    outmax: int
    pads: List[List[bytes]]  # pads[row_id][col]
    def derive_for_row(self, row_id: int, x: int) -> Tuple[int, bytes]:
        col = x % self.outmax
        return col, self.pads[row_id][col]

def main():
    banner("Construct synthetic public header")
    num_states = 4
    outmax = 2
    aid_bits = 8
    ns_bits = max(1, (num_states - 1).bit_length())  # 2
    cell_bits = 64
    pad_bits = cell_bits - (ns_bits + aid_bits)      # 54
    cell_bytes = cell_bits // 8                      # 8
    row_bytes  = outmax * cell_bytes                 # 16

    # Identity permutation; start at row 0
    perm = list(range(num_states))

    pub = GDFAPublicHeader(
        alphabet_size=256,
        outmax=outmax,
        cmax=2,
        num_states=num_states,
        start_row=0,
        permutation=perm,
        cell_bytes=cell_bytes,
        row_bytes=row_bytes,
        aid_bits=aid_bits,
    )

    banner("Forge rows & pads")
    # Pads for each row/col
    pads = [[os.urandom(cell_bytes) for _ in range(outmax)] for _ in range(num_states)]
    rows_bytes: List[bytes] = []

    # Define transitions:
    #  col 0: next = (row+1)%4, aid=0 except row==2 has aid=9 (to trigger stop)
    #  col 1: next = row (self-loop), aid=0
    for row in range(num_states):
        cells = []
        # col 0
        ns0 = (row + 1) % num_states
        aid0 = 9 if row == 2 else 0
        pt0 = _pack_cell(ns0, aid0, ns_bits, aid_bits, pad_bits, cell_bytes)
        ct0 = bytes(a ^ b for a, b in zip(pt0, pads[row][0]))
        cells.append(ct0)
        # col 1
        ns1, aid1 = row, 0
        pt1 = _pack_cell(ns1, aid1, ns_bits, aid_bits, pad_bits, cell_bytes)
        ct1 = bytes(a ^ b for a, b in zip(pt1, pads[row][1]))
        cells.append(ct1)
        rows_bytes.append(b"".join(cells))

    store = RowStore(pub, rows_bytes)
    oracle = FakeOracle(outmax=outmax, pads=pads)
    runner = GDFARunner(pub, store, oracle)

    banner("Evaluate on crafted input")
    # Input bytes all 0 → 每步選 col=0：0->1->2->(hit aid=9) 停
    res: EvalResult = runner.evaluate(b"\x00\x00\x00\x00", stop_on_first_attack=True)
    assert res.steps == 3
    assert res.first_attack_id == 9 and res.last_attack_id == 9
    print("[ONLINE] stop_on_first_attack works:", res)

    # Mixed input: 0,1,0,1 → 0->1 (col0)-> stays at 1 (col1)->2 (col0)->2 (col1)
    res2 = runner.evaluate(bytes([0,1,0,1]), stop_on_first_attack=False)
    assert res2.steps == 4
    # 最後一步在 row=2 用 col=1（aid=0），不觸發告警
    assert res2.last_attack_id == 0
    print("[ONLINE] full run without early stop:", res2)

    print("\nAll ONLINE evaluator tests passed ✔")

if __name__ == "__main__":
    main()
