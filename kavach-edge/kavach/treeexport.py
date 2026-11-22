"""Dependency-free gradient-boosted-tree runtime.

scikit-learn's HistGradientBoostingClassifier cannot be converted to ONNX by skl2onnx
(tested: TreeEnsembleClassifier node creation fails), and ONNX Runtime is awkward on
Termux / bionic.  So we export the trees ourselves into flat arrays and evaluate them
with NumPy.  Parity with sklearn is asserted to < 1e-9 in tests/test_models.py.

File format (``.npz``):  feature, threshold, left, right, value, miss_left, is_leaf  are
concatenated node arrays; ``roots`` gives the first node of every tree; ``tree_class``
says which class-column each tree adds to; ``baseline`` is the initial raw score.
The same arrays can be loaded 1:1 from Kotlin/C++.
"""
from __future__ import annotations

import json
import os
from typing import List

import numpy as np


def export_hgb(est, feature_names: List[str], path: str, meta: dict | None = None) -> None:
    feats, thr, left, right, val, miss, leaf, roots, tclass = [], [], [], [], [], [], [], [], []
    off = 0
    for it in est._predictors:
        for k, tp in enumerate(it):
            n = tp.nodes
            roots.append(off)
            tclass.append(k)
            feats.append(n["feature_idx"].astype(np.int32))
            thr.append(n["num_threshold"].astype(np.float64))
            # child indices become global
            left.append(np.where(n["is_leaf"], -1, n["left"].astype(np.int64) + off).astype(np.int32))
            right.append(np.where(n["is_leaf"], -1, n["right"].astype(np.int64) + off).astype(np.int32))
            val.append(n["value"].astype(np.float64))
            miss.append(n["missing_go_to_left"].astype(np.uint8))
            leaf.append(n["is_leaf"].astype(np.uint8))
            off += len(n)
    np.savez_compressed(
        path,
        feature=np.concatenate(feats), threshold=np.concatenate(thr),
        left=np.concatenate(left), right=np.concatenate(right), value=np.concatenate(val),
        miss_left=np.concatenate(miss), is_leaf=np.concatenate(leaf),
        roots=np.array(roots, np.int32), tree_class=np.array(tclass, np.int32),
        baseline=np.asarray(est._baseline_prediction, np.float64).reshape(-1),
        n_classes=np.int32(est.n_trees_per_iteration_ if est.n_trees_per_iteration_ > 1 else 2),
        meta=np.frombuffer(json.dumps({"feature_names": feature_names, **(meta or {})}).encode(), np.uint8),
    )


class TreeRuntime:
    """Pure-NumPy evaluator; vectorised over rows, loops over trees (<=~300 small trees)."""

    def __init__(self, path: str):
        z = np.load(path, allow_pickle=False)
        for k in ("feature", "threshold", "left", "right", "value", "miss_left", "is_leaf", "roots", "tree_class", "baseline"):
            setattr(self, k, z[k])
        self.n_classes = int(z["n_classes"])
        self.meta = json.loads(bytes(z["meta"]).decode())
        self.feature_names = self.meta["feature_names"]
        self.size_bytes = os.path.getsize(path)

    def raw(self, X: np.ndarray) -> np.ndarray:
        """Walk ALL trees at once: idx has shape (n_trees, n_rows) and we iterate one tree level per step (depth is ~6-8),
        so the Python-level loop count is the tree depth, not the number of trees. Output is bit-identical to the per-tree loop."""
        X = np.atleast_2d(np.asarray(X, np.float64))
        n = len(X)
        K = 1 if self.n_classes == 2 else self.n_classes
        out = np.tile(self.baseline.reshape(K, 1), (1, n)).astype(np.float64)
        T = len(self.roots)
        idx = np.repeat(self.roots.astype(np.int64)[:, None], n, axis=1)          # (T, n) current node of every tree for every row
        cols = np.arange(n)[None, :]
        leaf_all = self.is_leaf.astype(bool)
        miss_all = self.miss_left.astype(bool)
        for _ in range(64):                                                       # hard cap; real depth is far smaller
            leaf = leaf_all[idx]
            if leaf.all():
                break
            f = np.where(leaf, 0, self.feature[idx])
            xv = X[cols, f]
            go_left = np.where(np.isnan(xv), miss_all[idx], xv <= self.threshold[idx])
            nxt = np.where(go_left, self.left[idx], self.right[idx])
            idx = np.where(leaf, idx, nxt)
        vals = self.value[idx]                                                    # (T, n) leaf values
        for c in range(K):
            out[c] += vals[self.tree_class == c].sum(axis=0)
        return out

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        r = self.raw(X)
        if self.n_classes == 2:
            p = 1.0 / (1.0 + np.exp(-r[0]))
            return np.stack([1 - p, p], axis=1)
        e = np.exp(r - r.max(axis=0, keepdims=True))
        return (e / e.sum(axis=0, keepdims=True)).T
