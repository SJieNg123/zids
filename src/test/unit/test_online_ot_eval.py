# test/test_online_ot_eval.py
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import List, Tuple

from src.common.odfa.params import SecurityParams, SparsityParams, make_packing
from src.server.offline.gdfa_builder import GDFAPublicHeader
from src.server.online.ot_response_builder import RowAlphabet, build_row_ot_plan, make_row_ot_sender
from src.client.online.gdfa_evaluator import RowStore, GDFARunner, EvalResult
from src.client.online.ot_pad_oracle import OTPadOracle, TokenSource
from src.common.crypto.prf import prf_msg
from src.common.crypto.prg import G_bits
from src.common.utils.encode import i2osp
from src.common.crypto.ddh_group import DDHGroup  # for OT tables

def banner(s): print("\n======== " + s + " ========")

def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b

def _pack_cell(ns: int, aid: int, ns_bits: int, aid_bits: int, pad_bits: int, cell_bytes: int) -> bytes:
    v = ((ns << aid_bits) | aid) << pad_bits
    return v.to_bytes(cell_bytes, "big")

def _derive_cell_format(pub: GDFAPublicHeader):
    cell_bits = pub.cell_bytes * 8
    ns_bits   = max(1, (pub.num_states - 1).bit_length())
    aid_bits  = pub.aid_bits
    pad_bits  = cell_bits - (ns_bits + aid_bits)
    return cell_bits, ns_bits, aid_bits, pad_bits

# --- simple TokenSource that uses the chooser from ot_1of256 (server-provided for test only) ---
@dataclass
class LocalTokenSource(TokenSource):
    choosers: List   # one chooser per row
    def get_token(self, row_id: int, x: int) -> bytes:
        return self.choosers[row_id].choose(x)

def main():
    banner("Online-only test setup")

    # Security & packing
    sec = SecurityParams(k_bits=128, kprime_bits=128, kappa=128, alphabet_size=256)
    sp  = SparsityParams(outmax=3, cmax=2)
    pack = make_packing(sec, sp)

    # Public header (synthetic; permutation=identity for simplicity)
    num_states = 4
    perm = list(range(num_states))
    cell_bytes = _ceil_div(pack.gdfa_cell_pad_bits, 8)
    row_bytes = sp.outmax * cell_bytes
    pub = GDFAPublicHeader(
        alphabet_size=sec.alphabet_size,
        outmax=sp.outmax,
        cmax=sp.cmax,
        num_states=num_states,
        start_row=0,
        permutation=perm,
        cell_bytes=cell_bytes,
        row_bytes=row_bytes,
        aid_bits=8,   # pack 8-bit attack_id in cell
    )
    cell_bits, ns_bits, aid_bits, pad_bits = (pub.cell_bytes*8,
                                              max(1,(pub.num_states-1).bit_length()),
                                              pub.aid_bits,
                                              pub.cell_bytes*8 - (max(1,(pub.num_states-1).bit_length())+pub.aid_bits))

    # RowAlphabet: each symbol x belongs to exactly one column: x % outmax
    row_alpha = RowAlphabet(outmax=sp.outmax, cmax=sp.cmax,
                            sym_to_cols=[[i % sp.outmax] for i in range(256)])
    row_alpha.sanity_check()

    # For each row: build OT plan (generates GK[row][c] internally), then use GK to produce ciphertext row
    group = DDHGroup()
    choosers = []
    rows_bytes: List[bytes] = []
    gk_rows: List[List[bytes]] = []  # keep for building rows

    for row in range(num_states):
        plan, secrets = build_row_ot_plan(row, pub, pack, row_alpha, label_prefix=b"OT256|row=")
        _, chooser = make_row_ot_sender(group, plan)
        choosers.append(chooser)
        gk_rows.append(secrets.gk_by_col)

        # Build synthetic transitions using (row, col):
        # col 0: next=row+1 mod N, aid=0 except row==2 -> aid=9
        # col 1: self-loop, aid=0
        # col 2: goto 0, aid=0
        cells = []
        for c in range(sp.outmax):
            if c == 0:
                ns = (row + 1) % num_states
                aid = 9 if row == 2 else 0
            elif c == 1:
                ns = row; aid = 0
            else:
                ns = 0; aid = 0

            # Derive pad from GK -> seed -> PRG, consistent with client oracle
            info = b"ZIDS|SEED|row=" + i2osp(row, 4) + b"|col=" + i2osp(c, 2)
            seed = prf_msg(gk_rows[row][c], info, sec.k_bytes)
            pad  = G_bits(seed, cell_bits, label=b"PRG|GDFA|cell")
            pt   = _pack_cell(ns, aid, ns_bits, aid_bits, pad_bits, pub.cell_bytes)
            ct   = bytes(a ^ b for a, b in zip(pt, pad))
            cells.append(ct)

        rows_bytes.append(b"".join(cells))

    # Wire up store, oracle, runner
    store   = RowStore(pub, rows_bytes)
    tokens  = LocalTokenSource(choosers=choosers)
    oracle  = OTPadOracle(pub=pub, pack=pack, store=store, token_source=tokens)
    runner  = GDFARunner(pub, store, oracle)

    banner("Evaluate runs")
    # All 0 -> always pick col 0; path: 0->1->2->(aid=9) stop
    res: EvalResult = runner.evaluate(b"\x00\x00\x00\x00", stop_on_first_attack=True)
    assert res.steps == 3 and res.first_attack_id == 9
    print("[ONLINE] early stop works:", res)

    # Mixed symbols: 0,1,2,1 —> cols: 0,1,2,1
    res2 = runner.evaluate(bytes([0,1,2,1]), stop_on_first_attack=False)
    assert res2.steps == 4 and res2.last_attack_id == 0
    print("[ONLINE] full run OK:", res2)

    print("\nAll ONLINE OT-evaluator tests passed ✔")

if __name__ == "__main__":
    main()