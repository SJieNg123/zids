# common/ot/ot_1of256.py
from __future__ import annotations
from typing import List

from src.common.ot.ot_1ofm import OT1ofmSender, make_chooser
from src.common.utils.checks import ensure_fixed_bytes_table

def make_ot256_services(
    group,
    table_256: List[bytes],
    *,
    label: bytes = b"OT256",
    sid: bytes | None = None,
):
    """
    Thin wrapper over OT1ofm (m=256, BYTES mode).

    Args:
      group: DDHGroup
      table_256: list of 256 fixed-length byte entries (e.g., cmax*k' bytes each)
      label: domain-separation label (e.g., b"OT256|pos=I2OSP(pos,2)")
      sid: 16B salt for domain separation (None -> random inside OT1ofmSender)

    Returns:
      (svc, chooser)
        - svc:   OT1ofmSender (configured for bytes payload, m=256)
        - chooser: object with methods:
              choose(index:int) -> bytes
              choose_many(indices:bytes) -> List[bytes]
    """
    # Enforce 256 items & equal length
    ensure_fixed_bytes_table(table_256, 256, name="OT256.table")

    # Build the underlying 1-of-m sender in BYTES mode
    svc = OT1ofmSender(group, list(table_256), label=label, sid=sid)

    # Obtain the chooser function (signature: choose(_payload_unused, index) -> bytes/int)
    _choose_fn = make_chooser(group, label, svc)

    class _OT256Chooser:
        def __init__(self, choose_fn, service: OT1ofmSender):
            self._fn = choose_fn
            self._svc = service
            # For convenience to callers:
            self.entry_len = service.entry_length  # fixed length of each table entry (bytes)

        def choose(self, index: int) -> bytes:
            if not (0 <= index < 256):
                raise ValueError("index must be in 0..255")
            # payload arg is ignored by make_chooser-based chooser (kept for backward compatibility)
            return self._fn(None, index)

        def choose_many(self, indices: bytes) -> List[bytes]:
            return [self.choose(b) for b in indices]

    chooser = _OT256Chooser(_choose_fn, svc)
    return svc, chooser
