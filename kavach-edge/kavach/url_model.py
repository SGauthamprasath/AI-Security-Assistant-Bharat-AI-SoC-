"""Host-level phishing classifier = stack of (a) 30 lexical features -> gradient-boosted trees and
(b) hashed hostname character-n-grams -> logistic regression.  Both run in pure NumPy.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Tuple
from zlib import crc32

import numpy as np

from . import urlkit
from .treeexport import TreeRuntime

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
NG_DIM = 1 << 18


def host_ngram_features(host: str) -> Tuple[List[int], float]:
    """Hashed word / char-3-5-gram tokens of the host (TLD excluded - it is a separate numeric feature)."""
    sub, reg, suf = urlkit.registered_domain(host)
    s = (sub + "." + reg.split(".")[0]).strip(".") if "." in reg or sub else reg
    toks = set()
    for w in re.split(r"[^a-z0-9]+", s):
        if not w:
            continue
        toks.add("w:" + w)
        pw = "^" + w + "$"
        for n in (3, 4, 5):
            for i in range(len(pw) - n + 1):
                toks.add("c:" + pw[i:i + n])
    toks.add("tld:" + (suf or ""))
    idx = sorted({crc32(t.encode()) % NG_DIM for t in toks})
    return idx, (1.0 / np.sqrt(len(idx)) if idx else 0.0)


class UrlModel:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.rt = TreeRuntime(os.path.join(model_dir, "url_hgb.npz"))
        meta = json.load(open(os.path.join(model_dir, "url_hgb.json")))
        self.bias = meta["ngram_bias"]
        self.w = np.fromfile(os.path.join(model_dir, "url_ngram.bin"), dtype="<f4")
        self.stack = meta["stack"]  # {"w_tree","w_ngram","b"}
        self.size_bytes = self.rt.size_bytes + self.w.nbytes
        assert self.rt.feature_names == urlkit.FEATURE_NAMES, "feature order mismatch"

    def score_host(self, host: str) -> Dict[str, float]:
        x = urlkit.host_features(host)
        zt = float(self.rt.raw(x[None, :])[0, 0])
        idx, val = host_ngram_features(host)
        zn = self.bias + (float(self.w[idx].sum()) * val if idx else 0.0)
        z = self.stack["w_tree"] * zt + self.stack["w_ngram"] * zn + self.stack["b"]
        return {"z_tree": zt, "z_ngram": zn, "logit": z, "p": float(1 / (1 + np.exp(-z)))}

    def score_url(self, url: str) -> Dict[str, float]:
        return self.score_host(str(urlkit.parse_url(url)["host"]))
