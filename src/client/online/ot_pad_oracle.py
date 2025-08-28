# client/online/ot_pad_oracle.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, Tuple, List

from src.server.offline.gdfa_builder import GDFAPublicHeader
from src.client.online.gdfa_evaluator import PadOracle, RowStore  # uses same CellFormat derivation logic
from src.common.odfa.params import PackingParams
from src.common.crypto.prf import prf_msg
from src.common.crypto.prg import G_bits
from src.common.utils.encode import i2osp

def _ceil_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return (a + b - 1) // b

def _derive_cell_format(pub: GDFAPublicHeader):
    cell_bits = pub.cell_bytes * 8
    ns_bits = max(1, (pub.num_states - 1).bit_length())
    aid_bits = pub.aid_bits
    if ns_bits + aid_bits > cell_bits:
        raise ValueError("cell_bits too small for ns_bits + aid_bits")
    pad_bits = cell_bits - (ns_bits + aid_bits)
    cell_bytes = _ceil_div(cell_bits, 8)
    return cell_bits, cell_bytes, ns_bits, aid_bits, pad_bits

def _pack_info(row_id: int, col: int) -> bytes:
    return b"ZIDS|SEED|row=" + i2osp(row_id, 4) + b"|col=" + i2osp(col, 2)

class TokenSource(Protocol):
    """Return the OT token (bytes of length == cmax*k' bytes) for this (row, x)."""
    def get_token(self, row_id: int, x: int) -> bytes: ...

@dataclass
class OTPadOracle(PadOracle):
    """
    Online oracle that uses 1-of-256 OT tokens to find the unique (col, pad) per row & symbol.
    It needs access to RowStore to read the ciphertext row and test candidates.
    """
    pub: GDFAPublicHeader
    pack: PackingParams
    store: RowStore
    token_source: TokenSource

    def derive_for_row(self, row_id: int, x: int) -> Tuple[int, bytes]:
        cell_bits, cell_bytes, ns_bits, aid_bits, pad_bits = _derive_cell_format(self.pub)
        token = self.token_source.get_token(row_id, x)
        if len(token) != self.pack.cmax * self.pack.kprime_bytes:
            raise ValueError("token length mismatch")

        # split token into cmax keys (GK)
        gks: List[bytes] = [
            token[i*self.pack.kprime_bytes:(i+1)*self.pack.kprime_bytes]
            for i in range(self.pack.cmax)
        ]

        enc_row = self.store.get(row_id)

        # Try every column and every GK; accept the first that decrypts to a well-formed plaintext
        for c in range(self.pub.outmax):
            start = c * self.pub.cell_bytes
            ct = enc_row[start:start+self.pub.cell_bytes]
            for gk in gks:
                seed = prf_msg(gk, _pack_info(row_id, c), self.pack.k_bytes)
                pad  = G_bits(seed, cell_bits, label=b"PRG|GDFA|cell")
                pt   = bytes(a ^ b for a, b in zip(ct, pad))
                # validate plaintext: low pad_bits are zero; next-state is in range
                v = int.from_bytes(pt, "big")
                if (v & ((1 << pad_bits) - 1)) != 0:
                    continue
                v >>= pad_bits
                ns_mask = (1 << ns_bits) - 1
                ns = (v >> aid_bits) & ns_mask
                if 0 <= ns < self.pub.num_states:
                    return c, pad

        raise ValueError("no valid (col, pad) found for this row & symbol (invalid token?)")