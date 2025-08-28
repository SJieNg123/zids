# common/odfa/params.py
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict

# ================ helpers (local, no external deps) ================

def _ceil_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return (a + b - 1) // b

def _bytes_for_bits(nbits: int) -> int:
    if nbits < 0:
        raise ValueError("bit length must be non-negative")
    return _ceil_div(nbits, 8)

# ======================= core parameters ===========================

@dataclass(frozen=True)
class SecurityParams:
    """
    Cryptographic security knobs (paper-aligned):
      - k_bits:       seed length (in bits) used by PRG to expand PADs in GDFA (e.g., 128)
      - kprime_bits:  per-group key length (in bits) used inside ODFA/GDFA (e.g., 128)
      - kappa:        statistical parameter for OT extension/base-OT count (e.g., 128)
      - alphabet_size: |Σ|, default 256 for ASCII (ZIDS uses 1-of-256)
    """
    k_bits: int = 128
    kprime_bits: int = 128
    kappa: int = 128
    alphabet_size: int = 256

    def sanity_check(self) -> None:
        if self.k_bits <= 0 or self.kprime_bits <= 0 or self.kappa <= 0:
            raise ValueError("k, k', kappa must be positive")
        if self.alphabet_size <= 0:
            raise ValueError("|Σ| (alphabet_size) must be positive")
        # The paper speaks in bits; we require byte alignment to avoid ambiguous packing.
        if (self.k_bits % 8) != 0 or (self.kprime_bits % 8) != 0:
            raise ValueError("k_bits and kprime_bits must be multiples of 8 (byte-aligned)")

    @property
    def k_bytes(self) -> int:
        return _bytes_for_bits(self.k_bits)

    @property
    def kprime_bytes(self) -> int:
        return _bytes_for_bits(self.kprime_bits)

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)  # includes bits values; bytes are derived via props

@dataclass(frozen=True)
class SparsityParams:
    """
    DFA sparsity knobs obtained in offline analysis:
      - outmax: maximum out-degree kept per state after sparsification
      - cmax:   max number of character-groups any symbol belongs to
    Constraints: outmax >= 1, cmax >= 1, and cmax <= |Σ|.
    """
    outmax: int
    cmax: int

    def sanity_check(self, *, alphabet_size: int) -> None:
        if self.outmax <= 0:
            raise ValueError("outmax must be >= 1")
        if self.cmax <= 0:
            raise ValueError("cmax must be >= 1")
        if self.cmax > alphabet_size:
            raise ValueError("cmax cannot exceed |Σ|")

@dataclass(frozen=True)
class PackingParams:
    """
    All byte-level, fixed-size packing derived for ZIDS:
      - k_bytes, kprime_bytes: from SecurityParams
      - ot256_entry_len_bytes: length of each 1-of-256 table entry (bytes),
                               equals cmax * kprime_bytes (keys concatenated; pad with randomness if < cmax)
      - gdfa_pad_len_bits(row/col/cell): the PRG expansion length you should request when garbling cells.
        (We expose a single 'cell' length knob here; if you differentiate by cell type later,
         add fields or compute on demand.)
    """
    k_bytes: int
    kprime_bytes: int
    alphabet_size: int
    outmax: int
    cmax: int
    # Derived, fixed lengths:
    ot256_entry_len_bytes: int
    # If you need explicit bit counts for PRG expansion in GDFA cells, expose them:
    # For most uses you will expand to outmax * kprime_bits and XOR.
    gdfa_cell_pad_bits: int

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

# ================== factory: from high-level knobs ==================

def make_packing(sec: SecurityParams, sp: SparsityParams) -> PackingParams:
    """
    Compute all fixed lengths used by offline GDFA builder & online evaluator.
    Strictly enforces the constraints used in the paper:
      - 1-of-256 entries have constant length = cmax * k' (bytes)
      - GDFA cell pads are expanded by PRG to outmax * k' (bits)
    """
    sec.sanity_check()
    sp.sanity_check(alphabet_size=sec.alphabet_size)

    kB = sec.k_bytes
    kpB = sec.kprime_bytes

    # Each 1-of-256 "secret" S[x] is a concatenation of up to cmax keys of length k'
    ot256_entry_len_bytes = sp.cmax * kpB

    # When garbling a matrix cell, the pad typically covers 'outmax' keys of length k' bits.
    gdfa_cell_pad_bits = sp.outmax * sec.kprime_bits

    return PackingParams(
        k_bytes=kB,
        kprime_bytes=kpB,
        alphabet_size=sec.alphabet_size,
        outmax=sp.outmax,
        cmax=sp.cmax,
        ot256_entry_len_bytes=ot256_entry_len_bytes,
        gdfa_cell_pad_bits=gdfa_cell_pad_bits,
    )

# ============================== usage ==============================

# Example (no side effects; keep here for quick REPL sanity):
if __name__ == "__main__":
    sec = SecurityParams(k_bits=128, kprime_bits=128, kappa=128, alphabet_size=256)
    sp = SparsityParams(outmax=4, cmax=3)
    pk = make_packing(sec, sp)
    print("[params] sec:", sec.to_dict())
    print("[params] pack:", pk.to_dict())
