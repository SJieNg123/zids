# common/ot/ot_1of256.py (skeleton)
from common.ot.ot_1ofm import OT1ofmSender, make_chooser

def make_ot256_services(group, table_256: list[bytes], *, label=b"OT256", sid=None):
    if len(table_256) != 256:
        raise ValueError("table must have 256 entries")
    entry_len = len(table_256[0])
    if any(len(x) != entry_len for x in table_256):
        raise ValueError("all 256 entries must be fixed-length")
    svc = OT1ofmSender(group, table_256, label=label, sid=sid)
    chooser = make_chooser(group, label, svc)
    return svc, chooser, entry_len