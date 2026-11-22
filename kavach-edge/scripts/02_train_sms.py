#!/usr/bin/env python3
"""Step 2 - train the SMS/chat scam classifier (hashed n-gram logistic regression).

Why this model: it is a single linear layer over 2**18 hashed features.  Inference is a table lookup +
sum (~0.2 ms in Python, <0.05 ms in Kotlin/C++), the file is 1 MB, and the weights are directly
interpretable ("which words pushed this over the line").  We trade a little accuracy versus a
transformer for orders of magnitude lower latency / energy - the right trade on a phone SoC, and the
reasoning/explanation step is delegated to the Llama advisor anyway.
"""
import json
import os
import sys
import time

import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, log_loss, roc_auc_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import textnorm  # noqa: E402

MODELS = os.path.join(ROOT, "models")


def featurize(texts):
    indptr, indices, data = [0], [], []
    for t in texts:
        norm = textnorm.normalize_sms(t)
        idx, val = textnorm.text_features(norm, textnorm.meta_tokens(t))
        indices += idx
        data += [val] * len(idx)
        indptr.append(len(indices))
    return sp.csr_matrix((data, indices, indptr), shape=(len(texts), textnorm.HASH_DIM), dtype=np.float32)


def main():
    df = pd.read_csv(os.path.join(ROOT, "data", "processed", "sms_all.csv"))
    t0 = time.time()
    X = {s: featurize(df[df.split == s].text.tolist()) for s in ("train", "val", "test")}
    y = {s: df[df.split == s].label.values for s in ("train", "val", "test")}
    # hard negatives (formal legitimate notifications) are the costly mistake -> up-weight them
    wsrc = {"legit_synth": 1.5, "uci_ham": 1.0}
    sw = df[df.split == "train"].source.map(lambda s: wsrc.get(s, 1.0)).values
    print(f"featurised in {time.time()-t0:.1f}s  train={X['train'].shape}")

    best = None
    for C in (5, 10, 20, 40, 80):
        m = LogisticRegression(C=C, solver="liblinear", max_iter=300)
        m.fit(X["train"], y["train"], sample_weight=sw)
        z = m.decision_function(X["val"])
        ll = log_loss(y["val"], 1 / (1 + np.exp(-z)))
        auc = roc_auc_score(y["val"], z)
        print(f"  C={C:<3} val AUC={auc:.5f} logloss={ll:.4f}")
        if best is None or ll < best[0]:
            best = (ll, C, m)
    _, C, m = best
    # Platt calibration on the validation split (1-D logistic regression on the raw logit)
    zv = m.decision_function(X["val"]).reshape(-1, 1)
    cal = LogisticRegression(C=1e6, solver="lbfgs").fit(zv, y["val"])
    a, b = float(cal.coef_[0][0]), float(cal.intercept_[0])
    print(f"chosen C={C}  Platt a={a:.3f} b={b:.3f}")
    w = m.coef_[0].astype("<f4")
    w.tofile(os.path.join(MODELS, "sms_lr.bin"))
    json.dump({"dim": textnorm.HASH_DIM, "bias": float(m.intercept_[0]), "calib": {"a": a, "b": b}, "C": C,
               "hash": "crc32(utf8(token)) % dim; tokens: w:/b:/c:3-5/x:; value=1/sqrt(n_active)",
               "n_train": int(len(y["train"])), "nonzero_weights": int((w != 0).sum())},
              open(os.path.join(MODELS, "sms_lr.json"), "w"), indent=1)
    for s in ("val", "test"):
        z = a * m.decision_function(X[s]) + b
        print(f"{s}: AUC={roc_auc_score(y[s], z):.4f} AP={average_precision_score(y[s], z):.4f}")
    print("saved models/sms_lr.bin (%.2f MB)" % (os.path.getsize(os.path.join(MODELS, "sms_lr.bin")) / 1e6))


if __name__ == "__main__":
    main()
