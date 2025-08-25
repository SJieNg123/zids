# client/offline/param_setup.py
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Literal
import os

# Reuse your moved modules
from common.crypto.prg import G_bytes  # not used yet but reserved for future precomputation
from common.utils.encode import q_byte_len
from common.crypto.prf import prf_labeled  # reserved hook for domain-separated labels
from common.crypto import prg  # namespace when you want G_bits later
from common.crypto import prf  # namespace for PRF labels
from common.utils import encode  # i2osp/os2ip helpers if needed
from common.ot.base_ot2 import ddh_ot
from common.crypto.ddh_group import DDHGroup

# -----------------------------
# Security & public parameters
# -----------------------------

@dataclass(frozen=True)
class SecurityParams:
    """
    ZIDS cryptographic security knobs (paper-aligned names):

    - k_bits:    length (in bits) of per-cell pad seed for GDFA (e.g., 128)
    - kprime_bits: length (in bits) of a group key in ODFA/GDFA (e.g., 128)
    - kappa:     statistical security parameter for OT extension/base-OT count (e.g., 128)
    - alphabet_size: |Σ|, default 256 for ASCII (ZIDS uses 1-of-256)
    """
    k_bits: int = 128
    kprime_bits: int = 128
    kappa: int = 128
    alphabet_size: int = 256

    def sanity_check(self) -> None:
        if self.k_bits <= 0 or self.kprime_bits <= 0 or self.kappa <= 0:
            raise ValueError("Security parameters must be positive.")
        if self.alphabet_size <= 0:
            raise ValueError("alphabet_size must be positive.")
        # Require byte-aligned for convenience; if you prefer bit-accurate, relax this.
        if self.k_bits % 8 != 0 or self.kprime_bits % 8 != 0:
            raise ValueError("k_bits and kprime_bits must be byte-aligned (multiples of 8).")


@dataclass(frozen=True)
class PublicParams:
    """
    Public parameters sent from client to server in Step-0:
      - Group parameters (p, q, g)
      - Security parameters (k, k', kappa, |Σ|)
      - Optional: q_bytes (derived) to fix encoding length for Z_q values
    """
    p: int
    q: int
    g: int
    k_bits: int
    kprime_bits: int
    kappa: int
    alphabet_size: int
    q_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PublicParams":
        required = {"p", "q", "g", "k_bits", "kprime_bits", "kappa", "alphabet_size", "q_bytes"}
        missing = required - set(d.keys())
        if missing:
            raise ValueError(f"PublicParams.from_dict: missing fields {missing}")
        return PublicParams(
            p=int(d["p"]),
            q=int(d["q"]),
            g=int(d["g"]),
            k_bits=int(d["k_bits"]),
            kprime_bits=int(d["kprime_bits"]),
            kappa=int(d["kappa"]),
            alphabet_size=int(d["alphabet_size"]),
            q_bytes=int(d["q_bytes"]),
        )

@dataclass
class ClientOfflineState:
    """
    Client-side private state produced in Step-0 (kept local):

      - group: DDHGroup instance (same (p,q,g) as in PublicParams)
      - sec: security parameters
      - sid: random 16B session/domain-separation salt (use in labels for PRF/PRG)
      - base_ot_role: which role to take in base-OT for IKNP (sender/receiver), default per OT-256 design
      - ext_state: placeholder for OT extension precomputation (to be filled once IKNP is implemented)
    """
    group: DDHGroup
    sec: SecurityParams
    sid: bytes
    base_ot_role: Literal["sender", "receiver"] = "receiver"
    ext_state: Optional[Dict[str, Any]] = None  # to be populated by iknp_extension.setup(...)

# -----------------------------
# Group validation
# -----------------------------

def _validate_prime_order_subgroup(group: DDHGroup) -> None:
    """
    Strictly check that g has exact order q in Z_p^* (prime-order subgroup):
      - g^q ≡ 1 (mod p)
      - g^d != 1 for small d (spot-check); and g != 1
    NOTE: Full order proof is outside scope; we enforce the DDH subgroup checks you already use elsewhere.
    """
    p, q, g = group.p, group.q, group.g
    if not (2 < g < p - 1):
        raise ValueError("Invalid generator range.")
    if pow(g, q, p) != 1:
        raise ValueError("Generator g is not in the prime-order subgroup (g^q != 1).")
    if pow(g, 2, p) == 1:
        # quick-and-dirty guard against tiny order; with safe primes, order 2 would imply g=-1 mod p
        raise ValueError("Generator g has small order (g^2 == 1).")
    # Do not do expensive factorization; rely on safe-prime construction and above checks.

# -----------------------------
# Step-0 (GOT) API
# -----------------------------

def client_param_setup(group: DDHGroup, sec: SecurityParams,
                       *, base_ot_role: Literal["sender", "receiver"] = "receiver") -> tuple[PublicParams, ClientOfflineState]:
    """
    Create the client's Step-0 parameters & local state.

    Returns:
      - PublicParams: to send to server
      - ClientOfflineState: kept locally by client

    This does NOT perform network or base-OT extension yet. It only fixes:
      - security knobs (k, k', kappa, |Σ|)
      - group parameters (p, q, g)
      - per-session sid for domain separation
    """
    # 1) Sanity & group checks
    sec.sanity_check()
    _validate_prime_order_subgroup(group)

    # 2) Derive fixed encoding lengths
    q_bytes = q_byte_len(group.q)

    # 3) Prepare public bundle
    pp = PublicParams(
        p=group.p,
        q=group.q,
        g=group.g,
        k_bits=sec.k_bits,
        kprime_bits=sec.kprime_bits,
        kappa=sec.kappa,
        alphabet_size=sec.alphabet_size,
        q_bytes=q_bytes,
    )

    # 4) Prepare private state (domain separation salt for later labels)
    sid = os.urandom(16)
    st = ClientOfflineState(
        group=group,
        sec=sec,
        sid=sid,
        base_ot_role=base_ot_role,
        ext_state=None,  # to be filled by IKNP when available
    )
    return pp, st

# -----------------------------
# Helpers for future IKNP hook
# -----------------------------

def attach_extension_state(state: ClientOfflineState, ext_state: Dict[str, Any]) -> None:
    """
    Attach IKNP (or other) OT-extension precomputation results to the client state.
    Call this after you run iknp_extension.setup(...).
    """
    state.ext_state = dict(ext_state) if ext_state is not None else None


# -----------------------------
# Minimal smoke test (local)
# -----------------------------

if __name__ == "__main__":
    # Example usage with your DDHGroup constructor
    # NOTE: Replace with however you build your group in practice.
    g = DDHGroup()  # assume your DDHGroup picks a safe prime p, order q, and generator g
    sec = SecurityParams(k_bits=128, kprime_bits=128, kappa=128, alphabet_size=256)
    pp, st = client_param_setup(g, sec)

    print("[client] PublicParams:", pp.to_dict())
    print("[client] sid:", st.sid.hex())
    print("[client] base_ot_role:", st.base_ot_role)
