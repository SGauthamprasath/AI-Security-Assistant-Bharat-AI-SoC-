#!/usr/bin/env python3
"""Step 4 - network intrusion model on NSL-KDD (official KDDTrain+ / KDDTest+ split).

KDDTest+ contains attack *types never seen in training*, which is what makes it a fair (and hard)
generalisation test; accuracy there is ~15-20 points lower than random-split numbers that appear in
many papers.  We report the official split only.
"""
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
                             roc_curve, classification_report)
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import netkit  # noqa: E402
from kavach.treeexport import TreeRuntime, export_hgb  # noqa: E402

MODELS = os.path.join(ROOT, "models")
RAW = os.path.join(ROOT, "data", "raw")


def load(name):
    df = pd.read_csv(os.path.join(RAW, name), header=None, names=netkit.ALL_COLS + ["label", "difficulty"])
    df["cls"] = df.label.map(netkit.ATTACK_CATEGORY)
    assert df.cls.notna().all(), df[df.cls.isna()].label.unique()
    return df


def encode(df, services, cols):
    X = df[cols].copy()
    X["protocol_type"] = X.protocol_type.map(lambda v: netkit.PROTOCOLS.index(v) if v in netkit.PROTOCOLS else -1)
    X["service"] = X.service.map(lambda v: services.index(v) if v in services else services.index("other"))
    X["flag"] = X.flag.map(lambda v: netkit.FLAGS.index(v) if v in netkit.FLAGS else netkit.FLAGS.index("OTH"))
    return X.values.astype(np.float64)


def fit_eval(tag, cols, tr, te, services, save=False):
    Xtr_all, Xte = encode(tr, services, cols), encode(te, services, cols)
    ytr_all = tr.cls.map(netkit.CLASSES.index).values
    yte = te.cls.map(netkit.CLASSES.index).values
    Xtr, Xva, ytr, yva = train_test_split(Xtr_all, ytr_all, test_size=0.15, stratify=ytr_all, random_state=0)
    cnt = np.bincount(ytr, minlength=5)
    w = (cnt.max() / cnt) ** 0.5  # soften class imbalance (U2R has only ~50 samples)
    sw = w[ytr]
    m = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.08, max_leaf_nodes=31, l2_regularization=1.0, random_state=0).fit(Xtr, ytr, sample_weight=sw)
    # ---- calibrate P(attack) on the validation slice of TRAIN (no test peeking)
    pv = np.clip(1 - m.predict_proba(Xva)[:, 0], 1e-6, 1 - 1e-6)
    zv = np.log(pv / (1 - pv)).reshape(-1, 1)
    cal = LogisticRegression(C=1e6).fit(zv, (yva != 0).astype(int))
    a, b = float(cal.coef_[0][0]), float(cal.intercept_[0])
    P = m.predict_proba(Xte)
    pa = np.clip(1 - P[:, 0], 1e-6, 1 - 1e-6)
    zc = a * np.log(pa / (1 - pa)) + b
    yb = (yte != 0).astype(int)
    auc = roc_auc_score(yb, zc)
    fpr, tpr, thr = roc_curve(yb, zc)
    pred5 = P.argmax(1)
    predb = (pred5 != 0).astype(int)
    res = dict(tag=tag, n_features=len(cols), acc_bin=accuracy_score(yb, predb), prec=precision_score(yb, predb), rec=recall_score(yb, predb),
               f1=f1_score(yb, predb), fpr=float(((predb == 1) & (yb == 0)).sum() / (yb == 0).sum()), auc=auc, acc_5class=accuracy_score(yte, pred5),
               macro_f1_5class=f1_score(yte, pred5, average="macro"))
    print(f"[{tag}] features={len(cols)}  KDDTest+ binary: acc={res['acc_bin']:.4f} prec={res['prec']:.4f} recall={res['rec']:.4f} F1={res['f1']:.4f} FPR={res['fpr']:.4f} AUC={auc:.4f} | 5-class acc={res['acc_5class']:.4f} macroF1={res['macro_f1_5class']:.4f}")
    if save:
        print(classification_report(yte, pred5, target_names=netkit.CLASSES, digits=3, zero_division=0))
        cm = confusion_matrix(yte, pred5)
        print("confusion (rows=true, cols=pred):\n", cm)
        export_hgb(m, cols, os.path.join(MODELS, "net_hgb.npz"), {"classes": netkit.CLASSES})
        rt = TreeRuntime(os.path.join(MODELS, "net_hgb.npz"))
        print("export parity max|diff| =", float(np.abs(rt.predict_proba(Xte[:3000]) - P[:3000]).max()))
        json.dump({"services": services, "protocols": netkit.PROTOCOLS, "flags": netkit.FLAGS, "classes": netkit.CLASSES, "cols": cols,
                   "calib": {"a": a, "b": b}, "test": {k: (float(v) if not isinstance(v, str) else v) for k, v in res.items()},
                   "confusion": cm.tolist(), "val_n": int(len(yva))}, open(os.path.join(MODELS, "net_meta.json"), "w"), indent=1)
    return res


def main():
    tr, te = load("KDDTrain+.txt"), load("KDDTest+.txt")
    print("train", tr.shape, tr.cls.value_counts().to_dict(), "| test", te.shape, te.cls.value_counts().to_dict())
    services = sorted(set(tr.service) | set(te.service))
    if "other" not in services:
        services.append("other")
    r41 = fit_eval("all-41", netkit.ALL_COLS, tr, te, services)
    r28 = fit_eval("deployable-28", netkit.DEPLOY_COLS, tr, te, services, save=True)
    json.dump({"all41": r41, "deploy28": r28}, open(os.path.join(ROOT, "results", "net_ablation.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
