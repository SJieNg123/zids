# src/common/odfa/matrix.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Iterable, Tuple, Optional

# 對齊 earlier modules 的檢查介面；若不可用則退回本地實作
try:
    from src.common.utils.checks import ensure_index  # type: ignore
except Exception:
    def ensure_index(x: int, n: int, *, name: str = "index") -> None:
        if not isinstance(x, int):
            raise TypeError(f"{name} must be int")
        if not (0 <= x < n):
            raise ValueError(f"{name} out of range: {x} not in [0,{n})")


# =========================
# 基本 ODFA 結構（共用）
# =========================

@dataclass(frozen=True)
class ODFAEdge:
    """
    One outgoing transition kept in the sparsified ODFA row.
    - group_id: integer ID of a character-group for this row/edge (0..G-1 or any app-specific id space)
    - next_state: target state id (0..num_states-1) BEFORE permutation
    - attack_id:  integer label to emit on accept (0 means 'no attack'); pack as fixed bytes
    """
    group_id: int
    next_state: int
    attack_id: int = 0


@dataclass
class ODFARow:
    """
    A row after sparsification: at most outmax edges.
    If fewer than outmax, we will pad with dummy edges (self-loop to 0 with attack_id=0) during garbling.
    """
    edges: List[ODFAEdge]


@dataclass
class ODFA:
    """
    Minimal ODFA description needed by the builder.
    - num_states: number of states |Q|
    - start_state: initial state id (0..|Q|-1), BEFORE permutation
    - accepting: set/dict of accepting states -> attack_id (0 if none; >0 to tag)
    - rows: list of ODFARow, len == num_states; each row has <= outmax edges
    """
    num_states: int
    start_state: int
    accepting: Dict[int, int]
    rows: List[ODFARow]

    def sanity_check(self, outmax: int) -> None:
        if self.num_states <= 0:
            raise ValueError("ODFA must have at least one state")
        ensure_index(self.start_state, self.num_states, name="start_state")
        if len(self.rows) != self.num_states:
            raise ValueError("rows length must equal num_states")
        for s, row in enumerate(self.rows):
            if len(row.edges) > outmax:
                raise ValueError(f"row {s} has {len(row.edges)} edges > outmax={outmax}")
            for e in row.edges:
                ensure_index(e.next_state, self.num_states, name=f"row{s}.next_state")
                if e.attack_id < 0:
                    raise ValueError("attack_id must be >= 0")

    def max_outdeg(self) -> int:
        return max((len(r.edges) for r in self.rows), default=0)

    def avg_outdeg(self) -> float:
        if not self.rows:
            return 0.0
        return sum(len(r.edges) for r in self.rows) / float(len(self.rows))

# =========================
# RowAlphabet（單列的字元→欄位映射）
# =========================

@dataclass(frozen=True)
class RowAlphabet:
    """
    描述「在某一列 row 上，輸入符號 x ∈ [0..alphabet_size-1] 屬於哪些欄位」。
    - outmax: 欄位上限（須與對應列一致）
    - cmax:   單一符號在本列最多可屬於幾個欄位（論文中上限，用以固定 token 長度）
    - sym_to_cols[x]: 嚴格遞增列表，元素在 [0..outmax-1]，長度 <= cmax
    """
    outmax: int
    cmax: int
    alphabet_size: int
    sym_to_cols: List[List[int]]

    def sanity_check(self) -> None:
        if self.outmax <= 0 or self.cmax <= 0:
            raise ValueError("outmax and cmax must be positive")
        if self.alphabet_size <= 0:
            raise ValueError("alphabet_size must be positive")
        if len(self.sym_to_cols) != self.alphabet_size:
            raise ValueError("sym_to_cols length must equal alphabet_size")
        for x, cols in enumerate(self.sym_to_cols):
            if len(cols) > self.cmax:
                raise ValueError(f"symbol {x}: membership {len(cols)} > cmax={self.cmax}")
            last = -1
            for c in cols:
                ensure_index(c, self.outmax, name="col")
                if c <= last:
                    raise ValueError("sym_to_cols lists must be strictly increasing and unique")
                last = c

    def cols_of(self, x: int) -> List[int]:
        ensure_index(x, self.alphabet_size, name="symbol")
        return list(self.sym_to_cols[x])

    def invert(self) -> List[List[int]]:
        """
        產生欄位→符號的反向索引（僅供除錯/可視化），每欄位一個升冪列表。
        """
        cols: List[List[int]] = [[] for _ in range(self.outmax)]
        for x in range(self.alphabet_size):
            for c in self.sym_to_cols[x]:
                cols[c].append(x)
        return cols


# =========================
# 建立 RowAlphabet 的實用工具
# =========================

def make_row_alphabet_from_partition(
    outmax: int,
    cmax: int,
    *,
    alphabet_size: int = 256,
    cols_to_symbols: List[Iterable[int]],
) -> RowAlphabet:
    """
    從「欄位→符號集合」的分割描述建立 RowAlphabet。
    - cols_to_symbols: 長度必須 == outmax；每個元素是該欄位所包含的符號集合/迭代器
    - 符號可重複出現在不同欄位，但在單一欄位內不可重複
    - 每個符號的所屬欄位數量不可超過 cmax
    """
    if len(cols_to_symbols) != outmax:
        raise ValueError("cols_to_symbols length must equal outmax")

    sym_to_cols: List[List[int]] = [[] for _ in range(alphabet_size)]
    for c, bucket in enumerate(cols_to_symbols):
        seen: set[int] = set()
        for x in bucket:
            ensure_index(x, alphabet_size, name="symbol")
            if x in seen:
                raise ValueError(f"duplicate symbol {x} in column {c}")
            seen.add(x)
            lst = sym_to_cols[x]
            if len(lst) >= cmax:
                raise ValueError(f"symbol {x} assigned to more than cmax={cmax} columns")
            lst.append(c)

    # 強制每個符號的欄位列表遞增（上面已按欄位順序自然遞增）
    for x in range(alphabet_size):
        cols = sym_to_cols[x]
        cols.sort()
        # 唯一性已在 seen 中確認

    ra = RowAlphabet(outmax=outmax, cmax=cmax, alphabet_size=alphabet_size, sym_to_cols=sym_to_cols)
    ra.sanity_check()
    return ra


def make_row_alphabet_singleton(
    outmax: int,
    cmax: int,
    *,
    alphabet_size: int = 256,
    rule: Optional[callable] = None,
) -> RowAlphabet:
    """
    方便產生「互斥分群（每個符號只屬於 1 個欄位）」的 row 規則。
    - 預設規則：col = x % outmax
    - 可自訂 rule(x) -> col（需回傳 [0..outmax-1]）
    """
    if rule is None:
        rule = lambda x: x % outmax  # type: ignore[misc]

    cols_to_syms: List[List[int]] = [[] for _ in range(outmax)]
    for x in range(alphabet_size):
        c = int(rule(x))
        ensure_index(c, outmax, name="col")
        cols_to_syms[c].append(x)

    return make_row_alphabet_from_partition(outmax, cmax, alphabet_size=alphabet_size, cols_to_symbols=cols_to_syms)


def serialize_row_alphabet(ra: RowAlphabet) -> Dict[str, object]:
    """
    序列化為 JSON 友善格式（僅資料，不含類別名）。
    """
    ra.sanity_check()
    return {
        "outmax": ra.outmax,
        "cmax": ra.cmax,
        "alphabet_size": ra.alphabet_size,
        "sym_to_cols": ra.sym_to_cols,
    }


def deserialize_row_alphabet(obj: Dict[str, object]) -> RowAlphabet:
    """
    從 JSON 物件還原 RowAlphabet；做基本檢查。
    """
    required = ("outmax", "cmax", "alphabet_size", "sym_to_cols")
    missing = [k for k in required if k not in obj]
    if missing:
        raise ValueError(f"deserialize_row_alphabet: missing {missing}")
    outmax = int(obj["outmax"])           # type: ignore[arg-type]
    cmax = int(obj["cmax"])               # type: ignore[arg-type]
    alphabet_size = int(obj["alphabet_size"])  # type: ignore[arg-type]
    sym_to_cols = obj["sym_to_cols"]      # type: ignore[assignment]
    if not isinstance(sym_to_cols, list) or len(sym_to_cols) != alphabet_size:
        raise ValueError("sym_to_cols must be a list of length alphabet_size")
    # 深度檢查留給 RowAlphabet.sanity_check
    ra = RowAlphabet(outmax=outmax, cmax=cmax, alphabet_size=alphabet_size, sym_to_cols=sym_to_cols)  # type: ignore[arg-type]
    ra.sanity_check()
    return ra


# =========================
# 產生/檢查 ODFA 的輔助
# =========================

def pad_row_to_outmax(row: ODFARow, *, outmax: int) -> ODFARow:
    """
    複製一列並用 dummy 邊補到 outmax：group_id=-1, next_state=0, attack_id=0
    注意：不改動原物件；回傳新 ODFARow。
    """
    if len(row.edges) > outmax:
        raise ValueError(f"row has {len(row.edges)} edges > outmax={outmax}")
    padded = list(row.edges)
    while len(padded) < outmax:
        padded.append(ODFAEdge(group_id=-1, next_state=0, attack_id=0))
    return ODFARow(edges=padded)


def pad_all_rows(odfa: ODFA, *, outmax: int) -> ODFA:
    """
    回傳一個新 ODFA，所有列都補到 outmax。這對「離線打包前」常有用。
    """
    odfa.sanity_check(outmax)
    new_rows = [pad_row_to_outmax(r, outmax=outmax) for r in odfa.rows]
    return ODFA(num_states=odfa.num_states, start_state=odfa.start_state, accepting=dict(odfa.accepting), rows=new_rows)


def degree_stats(odfa: ODFA) -> Dict[str, float]:
    """
    回報一些稀疏化統計量，便於測試或儀表板顯示。
    """
    max_deg = 0
    min_deg = 1 << 30
    total = 0
    for r in odfa.rows:
        d = len(r.edges)
        max_deg = max(max_deg, d)
        min_deg = min(min_deg, d)
        total += d
    n = max(1, len(odfa.rows))
    return {
        "num_states": float(odfa.num_states),
        "min_outdeg": float(0 if min_deg == (1 << 30) else min_deg),
        "max_outdeg": float(max_deg),
        "avg_outdeg": float(total) / float(n),
    }


# =========================
# 最小 REPL 測試
# =========================

if __name__ == "__main__":
    # Tiny example: 3 states, outmax=2, cmax=1
    odfa = ODFA(
        num_states=3,
        start_state=0,
        accepting={2: 7},
        rows=[
            ODFARow([ODFAEdge(group_id=0, next_state=1, attack_id=0)]),
            ODFARow([ODFAEdge(group_id=1, next_state=2, attack_id=7)]),
            ODFARow([]),
        ],
    )
    odfa.sanity_check(outmax=2)
    print("[matrix] degree stats:", degree_stats(odfa))

    ra = make_row_alphabet_singleton(outmax=2, cmax=1, alphabet_size=256)
    inv = ra.invert()
    assert sum(len(bucket) for bucket in inv) == 256
    print("[matrix] row alphabet OK; col0 size =", len(inv[0]), "col1 size =", len(inv[1]))