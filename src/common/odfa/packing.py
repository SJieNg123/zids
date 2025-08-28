# src/common/odfa/packing.py
from __future__ import annotations
from dataclasses import dataclass

from src.common.odfa.params import PackingParams

def _ceil_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return (a + b - 1) // b

@dataclass(frozen=True)
class CellFormat:
    """
    Fixed layout (bits) of a single GDFA cell plaintext before PRG XOR.
    total_bits == ns_bits + aid_bits + pad_bits  (and should equal pack.gdfa_cell_pad_bits)
    """
    ns_bits: int
    aid_bits: int
    pad_bits: int

    @property
    def total_bits(self) -> int:
        return self.ns_bits + self.aid_bits + self.pad_bits

    @property
    def total_bytes(self) -> int:
        return _ceil_div(self.total_bits, 8)

def plan_cell_format(num_states: int, pack: PackingParams, *, aid_bits: int = 16) -> CellFormat:
    """
    Decide number of bits for next-state (after permutation) and attack_id,
    then fill the remainder with zero padding to reach pack.gdfa_cell_pad_bits.
    """
    if num_states <= 0:
        raise ValueError("num_states must be positive")
    ns_bits = max(1, (num_states - 1).bit_length())
    if aid_bits <= 0:
        raise ValueError("aid_bits must be positive")
    total_needed = ns_bits + aid_bits
    if total_needed > pack.gdfa_cell_pad_bits:
        raise ValueError(
            f"gdfa_cell_pad_bits ({pack.gdfa_cell_pad_bits}) too small for ns_bits({ns_bits})+aid_bits({aid_bits})"
        )
    pad_bits = pack.gdfa_cell_pad_bits - total_needed
    return CellFormat(ns_bits=ns_bits, aid_bits=aid_bits, pad_bits=pad_bits)
