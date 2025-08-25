# common/ot/base_ot2/iknp_extension.py
# this it not true iknp extention, just a wrapper

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, List, Union, Literal

from src.common.utils.encode import i2osp, os2ip, q_byte_len
from src.common.ot.base_ot2.ddh_ot import DDHOTSender, DDHOTReceiver

BytesLike = Union[bytes, bytearray]

# =========================
# Configuration (shared)
# =========================

@dataclass(frozen=True)
class OTExtConfig:
    """
    Security/config knobs for an OT 'extension' engine.
    - kappa: statistical security parameter; Direct backend ignores it (kept for API stability).
    """
    kappa: int = 128


# =========================
# Direct (fallback) backend
# =========================

class DirectOTExtension:
    """
    Direct, single-process *fallback* that batches many 1-of-2 OTs using the DDH base OT.
    This is NOT a true OT extension; it performs O(#OTs) base OT runs.
    We keep this to make the system runnable & testable now, while preserving a stable API.
    """

    def __init__(self, group, cfg: OTExtConfig = OTExtConfig()):
        self.group = group
        self.cfg = cfg
        self.q_bytes = q_byte_len(group.q)

    # -------- Bytes mode --------
    def batch_recv_bytes(
        self,
        choices: Iterable[int],
        m0_list: Iterable[BytesLike],
        m1_list: Iterable[BytesLike],
    ) -> List[bytes]:
        choices = list(choices)
        m0_list = list(m0_list)
        m1_list = list(m1_list)
        n = len(choices)
        if not (len(m0_list) == len(m1_list) == n):
            raise ValueError("batch_recv_bytes: length mismatch among inputs")
        if n == 0:
            return []

        L = len(m0_list[0])
        if any(len(x) != L for x in m0_list) or any(len(y) != L for y in m1_list):
            raise ValueError("batch_recv_bytes: all messages must have identical length")

        out: List[bytes] = []
        for j in range(n):
            bit = choices[j]
            if bit not in (0, 1):
                raise ValueError("batch_recv_bytes: choices must be 0/1")
            otS = DDHOTSender(self.group)
            otR = DDHOTReceiver(self.group, choice_bit=bit)
            B = otR.generate_B(otS.A)
            c0, c1 = otS.respond(B, bytes(m0_list[j]), bytes(m1_list[j]))
            out.append(otR.recover((c0, c1)))
        return out

    # -------- Int(Z_q) mode --------
    def batch_recv_ints(
        self,
        choices: Iterable[int],
        m0_list: Iterable[int],
        m1_list: Iterable[int],
    ) -> List[int]:
        choices = list(choices)
        m0_list = list(m0_list)
        m1_list = list(m1_list)
        n = len(choices)
        if not (len(m0_list) == len(m1_list) == n):
            raise ValueError("batch_recv_ints: length mismatch among inputs")
        if n == 0:
            return []

        # Encode ints to fixed-length q_bytes, reuse bytes path
        enc0: List[bytes] = []
        enc1: List[bytes] = []
        for a, b in zip(m0_list, m1_list):
            if not (isinstance(a, int) and isinstance(b, int)):
                raise TypeError("batch_recv_ints: messages must be ints")
            if not (1 <= a < self.group.q and 1 <= b < self.group.q):
                raise ValueError("batch_recv_ints: values must be in Z_q^* (1..q-1)")
            enc0.append(i2osp(a, self.q_bytes))
            enc1.append(i2osp(b, self.q_bytes))

        chosen_bytes = self.batch_recv_bytes(choices, enc0, enc1)

        # Decode back
        out: List[int] = []
        for cb in chosen_bytes:
            x = os2ip(cb)
            if not (1 <= x < self.group.q):
                raise ValueError("batch_recv_ints: decoded integer out of Z_q^*")
            out.append(x)
        return out


# =========================
# Thin wrapper facade
# =========================

class OTExtension:
    """
    Facade/wrapper with a stable API:
      - batch_recv_bytes(choices, m0_list, m1_list) -> List[bytes]
      - batch_recv_ints(choices, m0_list, m1_list) -> List[int]

    For now backend='direct' which calls DirectOTExtension (base OT in batch).
    Later you can switch backend='iknp' once a real IKNP engine is implemented.
    """

    def __init__(self, group, cfg: OTExtConfig = OTExtConfig(),
                 backend: Literal["direct", "iknp"] = "direct"):
        self.group = group
        self.cfg = cfg
        self.backend = backend

        if backend == "direct":
            self.impl = DirectOTExtension(group, cfg)
        elif backend == "iknp":
            # Temporarily fallback to direct until an IKNP engine is provided.
            # Keep the same external behavior.
            self.impl = DirectOTExtension(group, cfg)
        else:
            raise ValueError("Unknown OT extension backend")

    def batch_recv_bytes(
        self,
        choices: Iterable[int],
        m0_list: Iterable[BytesLike],
        m1_list: Iterable[BytesLike],
    ) -> List[bytes]:
        return self.impl.batch_recv_bytes(choices, m0_list, m1_list)

    def batch_recv_ints(
        self,
        choices: Iterable[int],
        m0_list: Iterable[int],
        m1_list: Iterable[int],
    ) -> List[int]:
        return self.impl.batch_recv_ints(choices, m0_list, m1_list)
