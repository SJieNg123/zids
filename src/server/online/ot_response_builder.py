# server/online/ot_response_builder.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Iterable, Tuple, Optional

import os

from src.common.odfa.params import SecurityParams, SparsityParams, PackingParams
from src.server.offline.gdfa_builder import GDFAPublicHeader, GDFASecrets
from src.common.crypto.prf import prf_msg
from src.common.crypto.prg import G_bits
from src.common.utils.encode import i2osp
from src.common.utils.checks import ensure_index, ensure_fixed_bytes_table
from src.common.ot.ot_1of256 import make_ot256_services


# =========================
# Row alphabet mapping
# =========================

@dataclass
class RowAlphabet:
    """
    描述「在某一列 row_id 上，輸入符號 x ∈ [0..255] 屬於哪些欄位（群組）」。
    - sym_to_cols[x] 是一個 *不重複且已排序* 的欄位索引列表（0..outmax-1），長度最多 cmax。
    - 若你的分群是互斥的，sym_to_cols[x] 就是單元素列表。
    """
    outmax: int
    cmax: int
    sym_to_cols: List[List[int]]  # len==256，元素為升冪整數列表

    def sanity_check(self) -> None:
        if len(self.sym_to_cols) != 256:
            raise ValueError("sym_to_cols must have length 256")
        for x, cols in enumerate(self.sym_to_cols):
            if len(cols) > self.cmax:
                raise ValueError(f"symbol {x}: membership {len(cols)} > cmax")
            last = -1
            for c in cols:
                ensure_index(c, self.outmax, name="col")
                if c <= last:
                    raise ValueError("sym_to_cols lists must be strictly increasing and unique")
                last = c


# =========================
# Online secrets (server-only)
# =========================

@dataclass
class RowOTSecrets:
    """
    伺服端線上用的祕密（單列）：
      - gk_by_col[c]: 此列第 c 欄位的 group key（k' bytes）
    Client 絕對不應直接看到 gk_by_col 以外欄位的 key。
    """
    gk_by_col: List[bytes]  # len==outmax, each len==kprime_bytes


@dataclass
class RowOTPlan:
    """
    伺服端為某列 row_id 準備的 1-of-256 OT 表，以及必要的中繼資料。
      - table_256: 256 項、每項長度固定為 entry_len = cmax * kprime_bytes
      - label:     供 ot_1of256 使用的域分離標籤（可包含 "row="）
      - entry_len: 方便呼叫端校驗
    """
    row_id: int
    table_256: List[bytes]
    label: bytes
    entry_len: int


# =========================
# Derivation rules (MUST match client)
# =========================

def derive_seed_from_gk(gk: bytes, row_id: int, col: int, k_bytes: int) -> bytes:
    """
    由欄位的 group key 導出 k 位 seed（固定長度 k_bytes）。
    Client 端必須用*同一規則*導出，才能算回正確 pad。
    """
    info = b"ZIDS|SEED|row=" + i2osp(row_id, 4) + b"|col=" + i2osp(col, 2)
    return prf_msg(gk, info, k_bytes)


def derive_pad_from_gk(gk: bytes, row_id: int, col: int, k_bytes: int, cell_bits: int) -> bytes:
    seed = derive_seed_from_gk(gk, row_id, col, k_bytes)
    return G_bits(seed, cell_bits, label=b"PRG|GDFA|cell")


# =========================
# Builder for one row
# =========================

def build_row_ot_plan(
    row_id: int,
    pub: GDFAPublicHeader,
    pack: PackingParams,
    row_alpha: RowAlphabet,
    *,
    label_prefix: bytes = b"OT256|row=",
) -> Tuple[RowOTPlan, RowOTSecrets]:
    """
    為指定 row 構建 1-of-256 OT 表：
      - 為每個欄位 c 取一把 GK[row][c]（k' bytes）
      - 為每個符號 x，把它所屬欄位的 GK 串接；若少於 cmax，補亂數 key 到固定長度
      - 回傳 (RowOTPlan, RowOTSecrets)
    注意：離線端 gdfa_builder 也必須用 *同一導出規則* 來產生 pad：
           seed_{row,c} = PRF(GK[row][c], "ZIDS|SEED|row|col", k_bytes)
           pad = PRG(seed_{row,c}, gdfa_cell_pad_bits, "PRG|GDFA|cell")
         這樣 Client 端用 token 中的 GK 才能解出正確那格。
    """
    row_alpha.sanity_check()

    outmax = row_alpha.outmax
    cmax = row_alpha.cmax
    kprime_bytes = pack.kprime_bytes
    k_bytes = pack.k_bytes
    cell_bits = pub.cell_bytes * 8
    entry_len = cmax * kprime_bytes

    # 1) 針對本列每個欄位，抽一把 group key（k' bytes）
    gk_by_col: List[bytes] = [os.urandom(kprime_bytes) for _ in range(outmax)]

    # 2) 生成 256 項 OT 表
    table: List[bytes] = []
    for x in range(256):
        cols = row_alpha.sym_to_cols[x]
        # 放入屬於此符號的欄位的 GK（可能是 1..cmax 把）
        chunks: List[bytes] = [gk_by_col[c] for c in cols]
        # 補齊到 cmax（用亂數填，避免洩漏群組數量）
        while len(chunks) < cmax:
            chunks.append(os.urandom(kprime_bytes))
        # 也可以隨機打亂 chunks 的順序以加強對抗結構分析（非必要）
        table.append(b"".join(chunks))

    plan = RowOTPlan(
        row_id=row_id,
        table_256=table,
        label=label_prefix + i2osp(row_id, 4),
        entry_len=entry_len,
    )
    secrets = RowOTSecrets(gk_by_col=gk_by_col)
    return plan, secrets


# =========================
# Hook: tie OT sender for this row
# =========================

def make_row_ot_sender(group, plan: RowOTPlan):
    """
    把本列的 OT 表交給 ot_1of256（它是 1-of-m 的薄包裝）。
    回傳 (svc, chooser) 其中 svc 是 Sender service；chooser 是（僅供本地 E2E 測試）用的 Client 端選擇器。
    真實部署時，伺服端只持有 svc，Client 只持有 chooser。
    """
    # 讓 ot_1of256 再做一次固定長度檢查（雙保險）
    ensure_fixed_bytes_table(plan.table_256, 256, name="row_ot.table")
    # 建 sender/chooser（注意：chooser 僅供本地測試，不應交給 Client 端以外的人）
    svc, chooser = make_ot256_services(
        group,
        plan.table_256,
        label=plan.label,
        sid=None,  # 讓 ot_1ofm 內部隨機化 sid
    )
    return svc, chooser


# =========================
# NOTE to offline builder
# =========================
#
# 為了讓線上 token 能正確解出「與離線密文相對應」的那格，請把
# server/offline/gdfa_builder.py 的 pad 產生方式改為：
#
#   # 先抽或讀入每列每欄位的 GK[row][c]（長度 = pack.kprime_bytes）
#   seed = prf_msg(GK[row][c], b"ZIDS|SEED|row=" + I2OSP(new_row,4) + b"|col=" + I2OSP(c,2), sec.k_bytes)
#   pad  = G_bits(seed, pack.gdfa_cell_pad_bits, label=b"PRG|GDFA|cell")
#   ct   = pt XOR pad
#
# 同時把這些 GK[row][c] 存入 server-only 的 secrets（例如新增一個結構或在 GDFASecrets 裡擴充）。
# 若離線期已用「純隨機 seed」建好密文，那線上用 GK 導出的 pad 將對不上——請務必採用上面的導出規則。
#
