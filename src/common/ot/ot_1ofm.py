# common/ot/ot_1ofm.py
from __future__ import annotations
import os
from typing import List, Union

from src.common.utils.encode import i2osp, os2ip, q_byte_len, xor_bytes
from src.common.crypto.prf import prf_msg
from src.common.ot.base_ot2.ddh_ot import DDHOTSender, DDHOTReceiver

PayloadItem = Union[int, bytes]

SEED_LEN = 32  # bytes; seeds for per-bit PRF pads
SID_LEN = 16   # bytes; per-service domain separation salt


def _bit_at_lsb(i: int, j: int) -> int:
    """Return the j-th bit of i with LSB-first convention."""
    return (i >> j) & 1


class OT1ofmSender:
    """
    1-of-m OT sender (composed from ℓ = ceil(log2 m) instances of 1-of-2 OT).

    Modes:
      - INT mode: payload is List[int], each in 1..q-1 (Z_q^*); ciphertexts length = q_bytes
      - BYTES mode: payload is List[bytes], all entries must have the same length entry_len

    Construction (standard "bit-decomposition + XOR of pads"):
      For each bit position j=0..ℓ-1 the sender samples a pair of seeds (s0_j, s1_j).
      The pad for option t is XOR_j PRF(s_{bit_j(t)}, info_j, L), where:
          info_j = label || b"|j=" || I2OSP(j,2) || b"|sid=" || sid
          L = q_bytes (INT mode) or entry_len (BYTES mode)
      Ciphertext for option t is ct_t = pt_t XOR pad_t.
      Receiver learns exactly one seed per j via ℓ runs of 1-of-2 OT, reconstructs pad_t*, and decrypts ct_t*.
    """

    def __init__(self, group, payload: List[PayloadItem], *, label: bytes, sid: bytes | None = None):
        if not isinstance(label, (bytes, bytearray)):
            raise TypeError("label must be bytes")
        self.group = group
        self.label = bytes(label)
        self.sid = sid or os.urandom(SID_LEN)

        self.m = len(payload)
        if self.m <= 0:
            raise ValueError("payload must be non-empty")

        # --- Detect mode and validate payload ---
        first = payload[0]
        if isinstance(first, int):
            self.mode = "INT"
            self.q_bytes = q_byte_len(group.q)
            self.entry_len = self.q_bytes
            self.plain: List[bytes] = []
            for x in payload:
                if not isinstance(x, int) or not (1 <= x < group.q):
                    raise ValueError("INT payload elements must be 1..q-1 (Z_q^*)")
                self.plain.append(i2osp(x, self.q_bytes))
        elif isinstance(first, (bytes, bytearray)):
            self.mode = "BYTES"
            self.entry_len = len(first)
            if self.entry_len <= 0:
                raise ValueError("BYTES payload entries must be non-empty and fixed-length")
            self.plain = []
            for b in payload:
                if not isinstance(b, (bytes, bytearray)) or len(b) != self.entry_len:
                    raise ValueError("All BYTES payload entries must have identical length")
                self.plain.append(bytes(b))
        else:
            raise TypeError("payload items must be int or bytes")

        # --- Bit-length ℓ = ceil(log2 m) ---
        self.l = (self.m - 1).bit_length()  # ℓ = 0 is possible if m=1, but m>=1 already checked

        # --- Sample per-bit seed pairs (s0_j, s1_j) and precompute ciphertexts ---
        # The sender knows all seeds; receiver will learn exactly one per j via 1-of-2 OTs.
        self.seed0: List[bytes] = [os.urandom(SEED_LEN) for _ in range(self.l)]
        self.seed1: List[bytes] = [os.urandom(SEED_LEN) for _ in range(self.l)]

        self.ciphertexts: List[bytes] = []
        for t in range(self.m):
            # Aggregate pad over bits j
            pad = bytearray(self.entry_len)
            for j in range(self.l):
                info = self.label + b"|j=" + i2osp(j, 2) + b"|sid=" + self.sid
                bit = _bit_at_lsb(t, j)
                seed = self.seed1[j] if bit else self.seed0[j]
                block = prf_msg(seed, info, self.entry_len)
                # XOR accumulate
                for k in range(self.entry_len):
                    pad[k] ^= block[k]
            ct = xor_bytes(self.plain[t], bytes(pad))
            self.ciphertexts.append(ct)

    # (Optional) helpers to expose configuration to the receiver/tests
    @property
    def entry_length(self) -> int:
        return self.entry_len

    @property
    def bit_length(self) -> int:
        return self.l


def make_chooser(group, label: bytes, service: OT1ofmSender):
    """
    Return a chooser function for the receiver:
        choose(payload_list_unused, index) -> Union[int, bytes]

    Notes:
      - 'payload_list_unused' is ignored (kept for backward compatibility with older runners).
      - Runs ℓ instances of 1-of-2 OT (Naor–Pinkas) to obtain per-bit seeds,
        reconstructs the pad, and decrypts the single chosen ciphertext.
      - Output type matches the service mode:
          * INT mode -> returns int in [1, q-1]
          * BYTES mode -> returns bytes of length `service.entry_length`
    """
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label must be bytes")
    label = bytes(label)

    def choose(_payload_unused, index: int):
        # --- Sanity checks ---
        if not (0 <= index < service.m):
            raise ValueError("index out of range")
        # If m==1 (ℓ==0), there are no bit-OTs; just decrypt with zero pad (all-zero XORs) -> ciphertext equals plaintext.
        # We still allow the generic code path; with ℓ==0 the loop below does nothing and pad stays all-zero.

        # --- Run ℓ 1-of-2 OTs to learn the correct seed per bit ---
        # Per j: Sender has (s0_j, s1_j); Receiver chooses bit = bit_j(index).
        learned_seeds: List[bytes] = []
        for j in range(service.l):
            bit = _bit_at_lsb(index, j)
            # Base OT session
            otS = DDHOTSender(group)
            otR = DDHOTReceiver(group, choice_bit=bit)
            B = otR.generate_B(otS.A)
            # Messages are the two seeds for this bit-position
            c0, c1 = otS.respond(B, service.seed0[j], service.seed1[j])
            seed_j = otR.recover((c0, c1))
            if len(seed_j) != SEED_LEN:
                # Defensive: base OT must return exactly the same seed length
                raise ValueError("Recovered seed has unexpected length")
            learned_seeds.append(seed_j)

        # --- Reconstruct pad and decrypt chosen ciphertext ---
        pad = bytearray(service.entry_len)
        for j, seed in enumerate(learned_seeds):
            info = label + b"|j=" + i2osp(j, 2) + b"|sid=" + service.sid
            block = prf_msg(seed, info, service.entry_len)
            for k in range(service.entry_len):
                pad[k] ^= block[k]

        pt_bytes = xor_bytes(service.ciphertexts[index], bytes(pad))

        if service.mode == "INT":
            x = os2ip(pt_bytes)
            # Optional: range check (keep strict consistency with INT mode contract)
            if not (1 <= x < group.q):
                raise ValueError("decrypted INT is out of expected Z_q^* range")
            return x
        else:
            return pt_bytes

    return choose
