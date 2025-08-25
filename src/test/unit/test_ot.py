# tests/test_ot.py
from __future__ import annotations
import os
import random
import sys
from typing import List

# --- adjust import roots if needed ---
# If your project root is not on sys.path, uncomment:
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.common.crypto.ddh_group import DDHGroup
from src.common.ot.base_ot2.ddh_ot import DDHOTSender, DDHOTReceiver
from src.common.ot.ot_1ofm import OT1ofmSender, make_chooser
from src.common.ot.ot_1of256 import make_ot256_services
from src.common.ot.base_ot2.iknp_extention import OTExtension, OTExtConfig
from src.common.utils.encode import q_byte_len
from src.common.utils.checks import ensure_fixed_bytes_table

# -----------------------
# helpers
# -----------------------

def flip_one_bit(b: bytes, bit_index: int = 0) -> bytes:
    """Flip 1 bit in a byte string (default: bit 0 of first byte)."""
    if len(b) == 0:
        return b
    ba = bytearray(b)
    byte_pos = bit_index // 8
    bit_off = bit_index % 8
    if byte_pos >= len(ba):
        byte_pos = 0
    ba[byte_pos] ^= (1 << bit_off)
    return bytes(ba)

def banner(msg: str):
    print("\n" + "="*8 + " " + msg + " " + "="*8)

# -----------------------
# tests
# -----------------------

def test_base_ot_ddh(group: DDHGroup):
    banner("1-of-2 (DDH) basic correctness")
    key_len = 32
    for bit in (0, 1):
        otS = DDHOTSender(group)
        otR = DDHOTReceiver(group, choice_bit=bit)
        B = otR.generate_B(otS.A)
        m0 = os.urandom(key_len)
        m1 = os.urandom(key_len)
        c0, c1 = otS.respond(B, m0, m1)
        out = otR.recover((c0, c1))
        exp = m0 if bit == 0 else m1
        assert out == exp, "DDH OT failed to recover chosen message"
    print("[OK] base OT recovered chosen messages for both bits")

def test_ot1ofm_bytes(group: DDHGroup):
    banner("OT 1-of-m (BYTES mode)")
    m = 17
    L = 48
    payload = [os.urandom(L) for _ in range(m)]
    label = b"TEST|BYTES"
    svc = OT1ofmSender(group, payload, label=label)  # BYTES mode auto-detected
    chooser = make_chooser(group, label, svc)

    for _ in range(200):
        idx = random.randrange(m)
        out = chooser(None, idx)
        assert out == payload[idx], "BYTES mode: wrong plaintext recovered"
    print("[OK] correctness on 200 random indices")

    # tamper a ciphertext; decryption should not equal original
    idx = random.randrange(m)
    orig = payload[idx]
    svc.ciphertexts[idx] = flip_one_bit(svc.ciphertexts[idx], 0)
    out_bad = chooser(None, idx)
    assert out_bad != orig, "BYTES mode: tamper did not break decryption (unexpected)"
    print("[OK] tamper check -> decryption differs from original (expected)")

    # label mismatch -> pad mismatch -> output differs
    chooser_bad = make_chooser(group, b"TEST|BYTES|MISMATCH", svc)
    idx2 = random.randrange(m)
    out_bad2 = chooser_bad(None, idx2)
    assert out_bad2 != payload[idx2], "BYTES mode: label mismatch should fail to recover"
    print("[OK] label mismatch check passed")

def test_ot1ofm_int(group: DDHGroup):
    banner("OT 1-of-m (INT mode)")
    m = 13
    q = group.q
    qbytes = q_byte_len(q)
    # Valid payload in 1..q-1
    payload = [random.randrange(1, q) for _ in range(m)]
    label = b"TEST|INT"
    svc = OT1ofmSender(group, payload, label=label)  # INT mode auto-detected
    chooser = make_chooser(group, label, svc)

    for _ in range(200):
        idx = random.randrange(m)
        out = chooser(None, idx)
        assert isinstance(out, int)
        assert out == payload[idx], "INT mode: wrong integer recovered"
    print("[OK] correctness on 200 random indices")

    # negative: invalid element 0 -> constructor should raise
    try:
        bad_payload = payload.copy()
        bad_payload[0] = 0
        _ = OT1ofmSender(group, bad_payload, label=label)
        raise AssertionError("INT mode: expected ValueError for element 0, but did not raise")
    except ValueError:
        print("[OK] invalid INT (0) rejected")

def test_ot256_wrapper(group: DDHGroup):
    banner("OT 1-of-256 wrapper (over 1-of-m)")
    L = 64
    table = [os.urandom(L) for _ in range(256)]
    svc, chooser = make_ot256_services(group, table, label=b"OT256|pos=00")

    # single choose
    for idx in (0, 1, 127, 128, 255):
        out = chooser.choose(idx)
        assert out == table[idx], f"OT256: wrong output at index {idx}"
    print("[OK] single index edge-cases")

    # choose_many
    indices = bytes([0, 127, 128, 255, 42, 200])
    outs = chooser.choose_many(indices)
    assert len(outs) == len(indices)
    for k, i in enumerate(indices):
        assert outs[k] == table[i], "OT256 choose_many mismatch"
    print("[OK] choose_many on sample set")

    # negative: unequal-length entries -> wrapper should reject
    try:
        bad = table.copy()
        bad[-1] = bad[-1] + b"\x00"  # make last entry longer
        ensure_fixed_bytes_table(bad, 256, name="OT256.table")  # should raise
        raise AssertionError("OT256: expected length check to fail but it passed")
    except ValueError:
        print("[OK] unequal-length table entries rejected (as expected)")

    # negative: out-of-range index
    try:
        chooser.choose(256)
        raise AssertionError("OT256: expected ValueError for index=256")
    except ValueError:
        print("[OK] index out-of-range rejected")

def test_direct_extension_bytes(group: DDHGroup):
    banner("DirectOTExtension (bytes) sanity")
    cfg = OTExtConfig(kappa=128)
    ext = OTExtension(group, cfg, backend="direct")
    L = 33
    n = 20
    choices = [random.randint(0, 1) for _ in range(n)]
    m0 = [os.urandom(L) for _ in range(n)]
    m1 = [os.urandom(L) for _ in range(n)]
    out = ext.batch_recv_bytes(choices, m0, m1)
    assert len(out) == n
    for j in range(n):
        exp = m0[j] if choices[j] == 0 else m1[j]
        assert out[j] == exp
    print("[OK] direct extension (bytes) returned correct selections")

def test_direct_extension_ints(group: DDHGroup):
    banner("DirectOTExtension (ints) sanity")
    cfg = OTExtConfig(kappa=128)
    ext = OTExtension(group, cfg, backend="direct")
    n = 20
    choices = [random.randint(0, 1) for _ in range(n)]
    m0 = [random.randrange(1, group.q) for _ in range(n)]
    m1 = [random.randrange(1, group.q) for _ in range(n)]
    out = ext.batch_recv_ints(choices, m0, m1)
    assert len(out) == n
    for j in range(n):
        exp = m0[j] if choices[j] == 0 else m1[j]
        assert out[j] == exp
    print("[OK] direct extension (ints) returned correct selections")

# -----------------------
# main
# -----------------------

def main():
    random.seed(1337)
    banner("Construct DDH group")
    group = DDHGroup()  # assumes your DDHGroup picks safe prime p, q and generator g
    # quick subgroup sanity (implicitly exercised in base OT & 1-of-m)

    test_base_ot_ddh(group)
    test_ot1ofm_bytes(group)
    test_ot1ofm_int(group)
    test_ot256_wrapper(group)
    test_direct_extension_bytes(group)
    test_direct_extension_ints(group)

    print("\nAll OT tests passed ✔")

if __name__ == "__main__":
    main()
