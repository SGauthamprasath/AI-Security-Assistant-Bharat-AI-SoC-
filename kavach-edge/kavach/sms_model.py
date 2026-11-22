"""Hashed n-gram logistic-regression scorer for scam messages (pure NumPy, ~1 MB, < 1 ms/message)."""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple
from zlib import crc32

import numpy as np

from . import textnorm

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


class SmsModel:
    def __init__(self, model_dir: str = MODEL_DIR):
        meta = json.load(open(os.path.join(model_dir, "sms_lr.json")))
        self.meta = meta
        self.dim = meta["dim"]
        self.bias = meta["bias"]
        self.calib_a, self.calib_b = meta["calib"]["a"], meta["calib"]["b"]
        self.w = np.fromfile(os.path.join(model_dir, "sms_lr.bin"), dtype="<f4")
        assert len(self.w) == self.dim
        self.size_bytes = self.w.nbytes

    def raw_logit(self, raw_text: str) -> Tuple[float, List[int], float]:
        norm = textnorm.normalize_sms(raw_text)
        idx, val = textnorm.text_features(norm, textnorm.meta_tokens(raw_text), self.dim)
        z = self.bias + (float(self.w[idx].sum()) * val if idx else 0.0)
        return z, idx, val

    def score(self, raw_text: str) -> Dict[str, float]:
        z, _, _ = self.raw_logit(raw_text)
        zc = self.calib_a * z + self.calib_b  # Platt-calibrated log-odds
        return {"raw_logit": z, "logit": zc, "p": float(_sigmoid(zc))}

    def top_tokens(self, raw_text: str, k: int = 5) -> List[Tuple[str, float]]:
        """Words that pushed the score towards 'scam' most (for explanations)."""
        norm = textnorm.normalize_sms(raw_text)
        words = textnorm._WORD_RE.findall(norm)
        contrib: Dict[str, float] = {}
        idx_all, val = textnorm.text_features(norm, textnorm.meta_tokens(raw_text), self.dim)
        for w in set(words):
            if w.endswith("tok") or len(w) < 3:
                continue
            i = crc32(("w:" + w).encode()) % self.dim
            contrib[w] = float(self.w[i]) * val
        out = sorted(contrib.items(), key=lambda kv: -kv[1])[:k]
        return [(w, c) for w, c in out if c > 0]
