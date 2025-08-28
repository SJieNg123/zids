# src/common/odfa/permutation.py
from __future__ import annotations
import os
from typing import List

def is_perm(perm: List[int], n: int) -> bool:
    if len(perm) != n: 
        return False
    seen = [False]*n
    for v in perm:
        if not (0 <= v < n) or seen[v]:
            return False
        seen[v] = True
    return True

def sample_perm(n: int) -> List[int]:
    """
    Fisher–Yates shuffle using os.urandom for unbiased randomness.
    Returns a permutation 'perm' mapping new_index -> old_index.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = int.from_bytes(os.urandom(2), "big") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

def inverse_perm(perm: List[int]) -> List[int]:
    """
    Compute inverse permutation inv such that inv[perm[i]] = i.
    """
    n = len(perm)
    inv = [0] * n
    for i, v in enumerate(perm):
        if not (0 <= v < n):
            raise ValueError("perm contains out-of-range value")
        inv[v] = i
    return inv
