# src/client/online/ot_query_builder.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Iterable, Optional, Dict
from collections import OrderedDict

from src.server.offline.gdfa_builder import GDFAPublicHeader
from src.common.odfa.params import PackingParams
from src.client.online.ot_pad_oracle import TokenSource  # 抽象來源；可能是 HTTP、測試 stub 等


@dataclass(frozen=True)
class OTQuery:
    """一筆 1-of-256 OT 查詢：在 row_id 上，對符號 x（0..255）取 token。"""
    row_id: int
    x: int

    def sanity_check(self, pub: GDFAPublicHeader) -> None:
        if not (0 <= self.row_id < pub.num_states):
            raise ValueError(f"row_id out of range: {self.row_id}")
        if not (0 <= self.x <= 255):
            raise ValueError(f"x must be a byte (0..255), got {self.x}")


class _LRUCache:
    """簡易 LRU，鍵為 (row_id, x)，值為 bytes token。"""
    def __init__(self, capacity: int):
        self.cap = max(0, int(capacity))
        self._map: OrderedDict[Tuple[int, int], bytes] = OrderedDict()

    def get(self, key: Tuple[int, int]) -> Optional[bytes]:
        if self.cap == 0:
            return None
        v = self._map.get(key)
        if v is not None:
            self._map.move_to_end(key)
        return v

    def put(self, key: Tuple[int, int], value: bytes) -> None:
        if self.cap == 0:
            return
        m = self._map
        if key in m:
            m.move_to_end(key)
            m[key] = value
            return
        m[key] = value
        if len(m) > self.cap:
            m.popitem(last=False)  # evict LRU


class OTQueryBuilder:
    """
    Client 端的 OT 查詢建構器／快取器。
    - 封裝 TokenSource：取得 (row_id, x) 的 1-of-256 token
    - 驗證 token 長度：必須等於 pack.cmax * pack.kprime_bytes
    - LRU 快取：避免相同 (row_id, x) 重複請求
    - 批次介面：批次查詢會自動去重並維持輸入順序輸出
    """
    def __init__(
        self,
        pub: GDFAPublicHeader,
        pack: PackingParams,
        token_source: TokenSource,
        *,
        enable_cache: bool = True,
        cache_capacity: int = 8192,
    ):
        self.pub = pub
        self.pack = pack
        self.token_source = token_source
        self._expected_len = pack.cmax * pack.kprime_bytes
        self._cache = _LRUCache(cache_capacity if enable_cache else 0)
        # 統計
        self.requests = 0       # 對 TokenSource 的實際請求次數
        self.cache_hits = 0     # LRU 命中次數

    # ---------------------------
    # 單筆
    # ---------------------------

    def get_token(self, row_id: int, x: int) -> bytes:
        """
        取得 (row_id, x) 的 token（bytes）。帶 LRU 快取與長度檢查。
        """
        q = OTQuery(row_id=row_id, x=x)
        q.sanity_check(self.pub)

        key = (row_id, x)
        cached = self._cache.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached

        token = self.token_source.get_token(row_id, x)
        if not isinstance(token, (bytes, bytearray)):
            raise TypeError("TokenSource.get_token must return bytes")
        token = bytes(token)
        if len(token) != self._expected_len:
            raise ValueError(
                f"token length mismatch: got {len(token)}, expect {self._expected_len} (cmax*k')"
            )

        self._cache.put(key, token)
        self.requests += 1
        return token

    # ---------------------------
    # 批次（去重、維持順序）
    # ---------------------------

    def get_tokens_batch(self, queries: Iterable[OTQuery]) -> List[bytes]:
        """
        針對多筆查詢回傳 tokens（按輸入順序），內部會自動去重並使用快取。
        """
        qs = list(queries)
        if not qs:
            return []

        # 檢查、去重
        unique_keys: Dict[Tuple[int, int], int] = {}  # key -> first index
        need_fetch: List[Tuple[int, int]] = []
        out: List[Optional[bytes]] = [None] * len(qs)

        for idx, q in enumerate(qs):
            if not isinstance(q, OTQuery):
                raise TypeError("queries must yield OTQuery objects")
            q.sanity_check(self.pub)
            key = (q.row_id, q.x)

            # 先看 cache
            cached = self._cache.get(key)
            if cached is not None:
                self.cache_hits += 1
                out[idx] = cached
                continue

            # 沒命中則登記 fetch，並記錄第一個出現位置
            if key not in unique_keys:
                unique_keys[key] = idx
                need_fetch.append(key)

        # 一一取回未命中的 token（目前 TokenSource 僅有單筆 API）
        for key in need_fetch:
            row_id, x = key
            token = self.token_source.get_token(row_id, x)
            if not isinstance(token, (bytes, bytearray)):
                raise TypeError("TokenSource.get_token must return bytes")
            token = bytes(token)
            if len(token) != self._expected_len:
                raise ValueError(
                    f"token length mismatch: got {len(token)}, expect {self._expected_len} (cmax*k')"
                )
            self._cache.put(key, token)
            self.requests += 1
            # 填回所有該 key 的位置（第一個位置一定存在）
            first_idx = unique_keys[key]
            # 先填第一個
            if out[first_idx] is None:
                out[first_idx] = token
            # 其餘相同 key 的位置也補上
            for idx, q in enumerate(qs):
                if out[idx] is None and (q.row_id, q.x) == key:
                    out[idx] = token

        # 最終保證無 None
        assert all(isinstance(t, (bytes, bytearray)) for t in out)
        return [bytes(t) for t in out]  # type: ignore[return-value]

    # ---------------------------
    # 輕量統計
    # ---------------------------

    def stats(self) -> dict:
        return {
            "requests": int(self.requests),
            "cache_hits": int(self.cache_hits),
            "cache_capacity": int(self._cache.cap),
            "expected_token_len": int(self._expected_len),
        }