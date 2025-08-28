# client/online/gdfa_evaluator.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Protocol, Optional

from src.common.odfa.params import SecurityParams, SparsityParams, PackingParams
from src.server.offline.gdfa_builder import GDFAPublicHeader, GDFASecrets  # secrets 僅供本地測試用
from src.common.crypto.prg import G_bits


# =========================
# Bit/packing helpers
# =========================

def _ceil_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return (a + b - 1) // b


@dataclass(frozen=True)
class CellFormat:
    """
    必須與 server/offline/gdfa_builder.py 的 CellFormat 對偶：
      total_bits = ns_bits + aid_bits + pad_bits == cell_bytes*8
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


def _derive_cell_format(pub: GDFAPublicHeader) -> CellFormat:
    cell_bits = pub.cell_bytes * 8
    ns_bits = max(1, (pub.num_states - 1).bit_length())
    aid_bits = pub.aid_bits
    if ns_bits + aid_bits > cell_bits:
        raise ValueError("cell_bits too small for ns_bits + aid_bits")
    pad_bits = cell_bits - (ns_bits + aid_bits)
    return CellFormat(ns_bits=ns_bits, aid_bits=aid_bits, pad_bits=pad_bits)


def _unpack_cell(pt: bytes, fmt: CellFormat) -> Tuple[int, int]:
    """
    解析明文 cell：MSB-first，結構為 [ns_bits | aid_bits | pad_bits(全0)]。
    回傳 (next_row_perm, attack_id)。
    """
    if len(pt) != fmt.total_bytes:
        raise ValueError("cell plaintext length mismatch")
    v = int.from_bytes(pt, "big")
    # 去掉 pad_bits（低位）
    v >>= fmt.pad_bits
    # 取出 ns 與 aid
    ns_mask = (1 << fmt.ns_bits) - 1
    aid_mask = (1 << fmt.aid_bits) - 1
    ns = (v >> fmt.aid_bits) & ns_mask
    aid = v & aid_mask
    return ns, aid


# =========================
# Row storage
# =========================

class RowStore:
    """
    以隨機訪問（按 row id）提供密文列（每列長度 = pub.row_bytes）。
    用法：
        store = RowStore.from_iter(pub, gdfa_rows_iterable)
        row_bytes = store.get(row_id)
    """
    def __init__(self, pub: GDFAPublicHeader, rows_by_id: List[bytes]):
        self.pub = pub
        self.rows = rows_by_id
        if len(self.rows) != pub.num_states:
            raise ValueError("RowStore length mismatch with num_states")
        for i, r in enumerate(self.rows):
            if len(r) != pub.row_bytes:
                raise ValueError(f"row {i} length {len(r)} != row_bytes {pub.row_bytes}")

    @staticmethod
    def from_iter(pub: GDFAPublicHeader, rows: Iterable[bytes]) -> "RowStore":
        rows_list = list(rows)
        return RowStore(pub, rows_list)

    def get(self, row_id: int) -> bytes:
        if not (0 <= row_id < self.pub.num_states):
            raise ValueError("row_id out of range")
        return self.rows[row_id]


# =========================
# Pad oracle abstraction
# =========================

class PadOracle(Protocol):
    """
    取得「此 row 對應輸入符號 x 的正確欄位 & pad」。
    回傳：
        (col_index, pad_bytes)  其中 0 <= col_index < outmax，len(pad_bytes) == pub.cell_bytes
    安全說明：
        在真實部署中，col_index 與 pad 應透過 OT 洩漏“恰一個”可解之欄位資訊；
        客戶端不應得知其餘欄位的 pad 或任何可驗證標記。
    """
    def derive_for_row(self, row_id: int, x: int) -> Tuple[int, bytes]:
        ...


class LocalSeedOracle(PadOracle):
    """
    僅供本地測試/端到端模擬用：
      - 使用 server 的 pad_seeds[new_row][col] 與同一 PRG 派生 pad
      - 欄位選擇策略由使用者提供（例如固定 0，或依 ODFA 的 group 對應）
    真實系統中，客戶端不會擁有 GDFASecrets。
    """
    def __init__(self, pub: GDFAPublicHeader, secrets: GDFASecrets,
                 col_selector: Optional[callable] = None):
        self.pub = pub
        self.secrets = secrets
        self.fmt = _derive_cell_format(pub)
        self.col_selector = col_selector or (lambda row_id, x: 0)

    def derive_for_row(self, row_id: int, x: int) -> Tuple[int, bytes]:
        col = int(self.col_selector(row_id, x))
        if not (0 <= col < self.pub.outmax):
            raise ValueError("col_selector returned out-of-range column")
        seed = self.secrets.pad_seeds[row_id][col]
        pad = G_bits(seed, self.fmt.total_bits, label=b"PRG|GDFA|cell")
        return col, pad


# =========================
# Evaluator
# =========================

@dataclass
class EvalResult:
    final_row: int
    first_attack_id: int
    last_attack_id: int
    steps: int


class GDFARunner:
    """
    單線程、常數記憶體的 GDFA 評估器。
    依序讀取輸入 bytes，從 start_row 開始，對每個 x:
      1) 透過 PadOracle 得到 (col, pad)
      2) 取該列密文中第 col 格的密文，XOR pad 解得明文 cell
      3) 解析明文，更新 current_row；若 attack_id > 0，可選擇提早返回
    """
    def __init__(self, pub: GDFAPublicHeader, store: RowStore, pad_oracle: PadOracle):
        self.pub = pub
        self.store = store
        self.pad_oracle = pad_oracle
        self.fmt = _derive_cell_format(pub)

    def _slice_cell(self, row_bytes: bytes, col: int) -> bytes:
        if not (0 <= col < self.pub.outmax):
            raise ValueError("col out of range")
        csz = self.pub.cell_bytes
        start = col * csz
        end = start + csz
        return row_bytes[start:end]

    def evaluate(self, data: bytes, *, stop_on_first_attack: bool = True) -> EvalResult:
        row = self.pub.start_row
        first_attack = 0
        last_attack = 0
        steps = 0

        for x in data:
            # 1) 取得該 row 的正確欄位與 pad（來源：OT 導出／本地測試 oracle）
            col, pad = self.pad_oracle.derive_for_row(row, x)
            if len(pad) != self.pub.cell_bytes:
                raise ValueError("pad length mismatch")

            # 2) 取出該欄位密文並解密
            enc_row = self.store.get(row)
            ct = self._slice_cell(enc_row, col)
            pt = bytes(a ^ b for a, b in zip(ct, pad))

            # 3) 解析明文，更新 row 與 attack 狀態
            ns, aid = _unpack_cell(pt, self.fmt)
            row = ns
            steps += 1
            if aid:
                last_attack = aid
                if first_attack == 0:
                    first_attack = aid
                if stop_on_first_attack:
                    return EvalResult(final_row=row, first_attack_id=first_attack,
                                      last_attack_id=last_attack, steps=steps)

        return EvalResult(final_row=row, first_attack_id=first_attack,
                          last_attack_id=last_attack, steps=steps)