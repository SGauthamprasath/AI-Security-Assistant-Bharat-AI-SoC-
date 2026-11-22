#!/usr/bin/env python3
"""Step 3 - train the host-level phishing model.

Design note (important for honest evaluation): benign training URLs are *hostnames from a domain
ranking*, phishing ones come from a threat feed.  Paths / schemes / ports differ systematically
between the two sources, so a model allowed to see them would learn the SOURCE, not maliciousness.
The learned model therefore sees HOST-level features only; path / query / scheme / port evidence is
scored by explicit rules (urlkit.url_rule_hits) whose weights are fitted in step 5.
"""
import json
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
import scipy.sparse as sp
from sklearn.metrics import log_loss, roc_auc_score, roc_curve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import urlkit  # noqa: E402
from kavach.treeexport import TreeRuntime, export_hgb  # noqa: E402
from kavach.url_model import NG_DIM, host_ngram_features  # noqa: E402

MODELS = os.path.join(ROOT, "models")


def main():
    df = pd.read_csv(os.path.join(ROOT, "data", "processed", "url_hosts.csv"))
    t0 = time.time()
    X = np.vstack([urlkit.host_features(h) for h in df.host])
    print(f"features {X.shape} in {time.time()-t0:.0f}s")
    np.save(os.path.join(ROOT, "data", "processed", "url_X.npy"), X)
    y = df.label.values
    spl = df.split.values
    tr, va, te = (spl == "train"), (spl == "val"), (spl == "test")
    best = None
    for it, lr, leaves in [(120, 0.1, 31), (250, 0.08, 31), (250, 0.08, 63)]:
        m = HistGradientBoostingClassifier(max_iter=it, learning_rate=lr, max_leaf_nodes=leaves, l2_regularization=1.0,
                                           early_stopping=False, random_state=0).fit(X[tr], y[tr])
        p = m.predict_proba(X[va])[:, 1]
        ll = log_loss(y[va], np.clip(p, 1e-6, 1 - 1e-6))
        print(f"  iters={it} lr={lr} leaves={leaves}: val AUC={roc_auc_score(y[va], p):.4f} logloss={ll:.4f}")
        if best is None or ll < best[0]:
            best = (ll, m, (it, lr, leaves))
    _, m, cfg = best
    export_hgb(m, urlkit.FEATURE_NAMES, os.path.join(MODELS, "url_hgb.npz"), {"cfg": cfg})
    rt = TreeRuntime(os.path.join(MODELS, "url_hgb.npz"))
    ref = m.decision_function(X[te][:2000])
    print("tree export parity max|diff| =", float(np.abs(ref - rt.raw(X[te][:2000])[0]).max()))

    # ---- (b) hostname n-gram logistic regression
    t0 = time.time()
    def mat(hs):
        ip, ind, dat = [0], [], []
        for h in hs:
            i, v = host_ngram_features(h)
            ind += i
            dat += [v] * len(i)
            ip.append(len(ind))
        return sp.csr_matrix((dat, ind, ip), shape=(len(hs), NG_DIM), dtype=np.float32)
    M = {k: mat(df.host[mask]) for k, mask in (("train", tr), ("val", va), ("test", te))}
    print(f"n-gram features in {time.time()-t0:.0f}s")
    lr = LogisticRegression(C=4, solver="liblinear").fit(M["train"], y[tr])
    lr.coef_[0].astype("<f4").tofile(os.path.join(MODELS, "url_ngram.bin"))
    zt_v, zn_v = m.decision_function(X[va]), lr.decision_function(M["val"])
    print(f"  val AUC: trees={roc_auc_score(y[va], zt_v):.4f}  ngram={roc_auc_score(y[va], zn_v):.4f}")
    st = LogisticRegression(C=1e6).fit(np.c_[zt_v, zn_v], y[va])
    wt, wn = [float(v) for v in st.coef_[0]]
    sb = float(st.intercept_[0])
    json.dump({"cfg": cfg, "features": urlkit.FEATURE_NAMES, "ngram_bias": float(lr.intercept_[0]),
               "stack": {"w_tree": wt, "w_ngram": wn, "b": sb}}, open(os.path.join(MODELS, "url_hgb.json"), "w"), indent=1)
    zt_t, zn_t = m.decision_function(X[te]), lr.decision_function(M["test"])
    z = wt * zt_t + wn * zn_t + sb
    fpr, tpr, _ = roc_curve(y[te], z)
    print(f"STACK weights tree={wt:.2f} ngram={wn:.2f}")
    print(f"TEST  trees AUC={roc_auc_score(y[te], zt_t):.4f} | ngram AUC={roc_auc_score(y[te], zn_t):.4f} | STACK AUC={roc_auc_score(y[te], z):.4f}  TPR@FPR1%={tpr[np.searchsorted(fpr, 0.01)]:.3f}  TPR@FPR0.1%={tpr[np.searchsorted(fpr, 0.001)]:.3f}")
    imp = sorted(zip(urlkit.FEATURE_NAMES, _perm_importance(m, X[va], y[va])), key=lambda kv: -kv[1])[:10]
    print("top features (val permutation importance, AUC drop):", [(k, round(v, 4)) for k, v in imp])
    print("size: trees %.0f KB + ngram %.0f KB" % (os.path.getsize(os.path.join(MODELS, "url_hgb.npz")) / 1e3, os.path.getsize(os.path.join(MODELS, "url_ngram.bin")) / 1e3))


def _perm_importance(m, X, y, n=6000):
    rng = np.random.RandomState(0)
    idx = rng.choice(len(X), min(n, len(X)), replace=False)
    Xs, ys = X[idx], y[idx]
    base = roc_auc_score(ys, m.predict_proba(Xs)[:, 1])
    out = []
    for j in range(X.shape[1]):
        Xp = Xs.copy()
        Xp[:, j] = rng.permutation(Xp[:, j])
        out.append(base - roc_auc_score(ys, m.predict_proba(Xp)[:, 1]))
    return out


if __name__ == "__main__":
    main()
