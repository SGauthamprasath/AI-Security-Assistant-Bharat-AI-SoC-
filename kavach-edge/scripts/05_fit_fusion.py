#!/usr/bin/env python3
"""Step 5 - fit risk-fusion weights and choose alert thresholds.

Data used (never the locked test set):
  * composite messages built from the SMS *validation* split + URL *validation* hosts
    (scam text + phishing URL / legit text + popular-domain URL; see build_composites)
  * the DEV hand-written benchmark (data/kavachbench_in.jsonl, weight x5) so the stacker also sees
    out-of-distribution phrasing
Thresholds: DANGEROUS = lowest score with <=0.5 % false alarms, SUSPICIOUS = <=3 % (message level);
they are picked on the same data with weighted quantiles.
"""
import collections
import json
import os
import random
import string
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import fusion, netkit, sms_rules, textnorm, urlkit  # noqa: E402
from kavach.sms_model import SmsModel  # noqa: E402
from kavach.url_model import UrlModel  # noqa: E402

rng = random.Random(2026)
BENIGN_PATHS = ["/", "/", "/", "/about", "/contact", "/products/12345", "/blog/2024/05/new-features", "/login", "/account/orders", "/signin", "/help/faq",
                "/news/article/88123", "/search?q=phone", "/category/electronics", "/user/profile", "/verify-email?token=abc123", "/en/home", "/pricing",
                "/download", "/support/ticket/55", "/track?id=88213", "/offers", "/careers", "/privacy-policy", "/orders/details/9981", "/pay/invoice/4412"]


def load_phish_urls():
    m = {}
    for line in open(os.path.join(ROOT, "data", "raw", "phishing_links_active.txt"), errors="ignore"):
        line = line.strip()
        h = urlkit.parse_url(line)["host"]
        if h and h not in m:
            m[h] = line
    return m


def benign_url(host):
    return ("https://" if rng.random() < 0.9 else "http://") + host + rng.choice(BENIGN_PATHS)


def short_url():
    s = rng.choice(sorted(urlkit.SHORTENERS - {"wa.me"}))
    return "https://" + s + "/" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(7))


def weighted_threshold(scores, y, w, fpr):
    neg = y == 0
    s, ww = scores[neg], w[neg]
    o = np.argsort(s)
    s, ww = s[o], ww[o]
    cum = np.cumsum(ww) / ww.sum()
    k = np.searchsorted(cum, 1 - fpr)
    return float(s[min(k, len(s) - 1)]) + 1e-9


def main():
    sms_m, url_m = SmsModel(), UrlModel()
    phish_full = load_phish_urls()
    uh = pd.read_csv(os.path.join(ROOT, "data", "processed", "url_hosts.csv"))
    uh = uh[uh.split == "val"]
    ph = uh[uh.label == 1].host.tolist()
    bh_top = uh[(uh.label == 0) & (uh["rank"] <= 50000)].host.tolist()
    bh_any = uh[uh.label == 0].host.tolist()

    # ------------------------------------------------------------------ URL-only stacker
    def url_set(n_each):
        rows = []
        for h in rng.sample(ph, min(n_each, len(ph))):
            rows.append((phish_full.get(h, "http://" + h + "/"), 1, 1.0))
        for h in rng.sample(bh_any, min(n_each, len(bh_any))):
            rows.append((benign_url(h), 0, 1.0))
        return rows

    def featurise_url(rows):
        X, y, w = [], [], []
        for u, lab, wt in rows:
            ents, z, hits = _ents(u)
            if not ents:
                continue
            X.append(fusion.url_vector(z[0], hits[0])); y.append(lab); w.append(wt)
        return np.array(X), np.array(y), np.array(w)

    def _ents(u):
        p = urlkit.parse_url(u)
        host = p["host"]
        if not host:
            return [], [], []
        sc = url_m.score_host(host)
        return [1], [sc["logit"]], [[h[0] for h in urlkit.url_rule_hits(u)]]

    dev_urls = [json.loads(l) for l in open(os.path.join(ROOT, "data", "kavachbench_urls.jsonl"))]
    rows = url_set(6000) + [(r["url"], r["label"], 5.0) for r in dev_urls]
    Xu, yu, wu = featurise_url(rows)
    w_u, b_u = fusion.fit_constrained_lr(Xu, yu, fusion.URL_FEATURES, wu, lam=30.0)
    zu = Xu @ w_u + b_u
    th_url = {"dangerous": weighted_threshold(fusion.sigmoid(zu), yu, wu, 0.005), "suspicious": weighted_threshold(fusion.sigmoid(zu), yu, wu, 0.03)}
    print("URL stacker: n=%d  thresholds=%s" % (len(yu), {k: round(v, 3) for k, v in th_url.items()}))

    # ------------------------------------------------------------------ message stacker
    sm = pd.read_csv(os.path.join(ROOT, "data", "processed", "sms_all.csv"))
    sm = sm[sm.split == "val"]
    comp = []
    for t, lab in zip(sm.text, sm.label):
        r = rng.random()
        if lab == 1:
            if r < 0.40: urls = []
            elif r < 0.88: urls = [phish_full.get(h, "http://" + h + "/") for h in [rng.choice(ph)]]
            elif r < 0.96: urls = [short_url()]
            else: urls = [phish_full.get(rng.choice(ph), "http://x.top/")] + [phish_full.get(rng.choice(ph), "http://y.top/")]
        else:
            if r < 0.55: urls = []
            elif r < 0.92: urls = [benign_url(rng.choice(bh_top if rng.random() < 0.7 else bh_any))]
            elif r < 0.96: urls = [short_url()]
            else: urls = [benign_url(rng.choice(bh_top)), benign_url(rng.choice(bh_top))]
        txt = t
        for u in urls:
            if "<URL>" in txt:
                txt = txt.replace("<URL>", u, 1)
            else:
                txt = txt + " " + u
        comp.append((txt, None, lab, 1.0))
    dev = [json.loads(l) for l in open(os.path.join(ROOT, "data", "kavachbench_in.jsonl"))]
    comp += [(r["text"], r["sender"], r["label"], 5.0) for r in dev]

    def featurise_msg(items):
        X, y, w = [], [], []
        for txt, sender, lab, wt in items:
            norm = textnorm.normalize_sms(txt)
            sc = sms_m.score(txt)
            hits = [h["id"] for h in sms_rules.sms_rule_hits(txt, norm, sender)]
            urls = textnorm.extract_urls(txt)
            uz, uh_ = [], []
            for u in urls:
                p = urlkit.parse_url(u)
                if p["host"]:
                    uz.append(url_m.score_host(p["host"])["logit"]); uh_.append([h[0] for h in urlkit.url_rule_hits(u)])
            X.append(fusion.message_vector(sc["logit"], uz, hits, uh_)); y.append(lab); w.append(wt)
        return np.array(X), np.array(y), np.array(w)

    Xm, ym, wm = featurise_msg(comp)
    print(f"message stacker: n={len(ym)} (val composite {len(sm)} + dev {len(dev)}), scam share {ym.mean():.2f}")
    # baseline: model-only (z_sms) AUC on dev part for the log
    w_m, b_m = fusion.fit_constrained_lr(Xm, ym, fusion.MSG_FEATURES, wm, lam=30.0)
    zm = Xm @ w_m + b_m
    pm = fusion.sigmoid(zm)
    th_msg = {"dangerous": weighted_threshold(pm, ym, wm, 0.005), "suspicious": weighted_threshold(pm, ym, wm, 0.03)}
    print("message thresholds:", {k: round(v, 3) for k, v in th_msg.items()})

    # ------------------------------------------------------------------ network thresholds (NSL-KDD validation slice)
    from kavach.netkit import NetModel
    nm = NetModel()
    tr = pd.read_csv(os.path.join(ROOT, "data", "raw", "KDDTrain+.txt"), header=None, names=netkit.ALL_COLS + ["label", "difficulty"])
    tr["cls"] = tr.label.map(netkit.ATTACK_CATEGORY)
    X = np.vstack([netkit.encode_row(r, nm.meta) for r in tr[netkit.DEPLOY_COLS].to_dict("records")])
    yc = tr.cls.map(netkit.CLASSES.index).values
    from sklearn.model_selection import train_test_split as tts
    cols_all = netkit.ALL_COLS  # same split as 04 (it split the 41-col / 28-col frames with identical random_state & stratify)
    idx = np.arange(len(yc))
    _, iva = tts(idx, test_size=0.15, stratify=yc, random_state=0)
    pn = nm.predict(X[iva])["p_attack"]
    yb = (yc[iva] != 0).astype(int)
    in_dist = {"dangerous": float(fusion.threshold_at_fpr(pn, yb, 0.005)), "suspicious": float(fusion.threshold_at_fpr(pn, yb, 0.02))}
    # The in-distribution validation slice is "too easy" (99.5th pct of normal p_attack is ~0.02), so thresholds taken from it
    # would flag far too much unseen traffic (KDDTest+ has attack types absent from training).  We therefore use conservative
    # round thresholds and publish the KDDTest+ operating curve (results/net_operating_curve.csv) instead of tuning on it.
    th_net = {"dangerous": 0.9, "suspicious": 0.5}
    print("network thresholds: in-distribution-derived", {k: round(v, 4) for k, v in in_dist.items()}, "-> using", th_net)

    np.savez_compressed(os.path.join(ROOT, "data", "processed", "fusion_fit.npz"), Xm=Xm, ym=ym, wm=wm, Xu=Xu, yu=yu, wu=wu)  # for ablations in 06
    out = {
        "message": {"weights": dict(zip(fusion.MSG_FEATURES, map(float, w_m))), "bias": float(b_m)},
        "url": {"weights": dict(zip(fusion.URL_FEATURES, map(float, w_u))), "bias": float(b_u)},
        "network": {"rule_weight": 1.0, "rule_cap": 3.0},
        "thresholds": {"message": th_msg, "url": th_url, "network": th_net},
        "fit": {"n_message": int(len(ym)), "n_url": int(len(yu)), "lam": 30.0, "dev_weight": 5.0,
                "protocol": "val composite + DEV benchmark; locked TEST never used"},
    }
    json.dump(out, open(os.path.join(ROOT, "models", "fusion.json"), "w"), indent=1)
    # human-readable weight table for the report
    prior = sms_rules.prior_weights()
    prior.update({k: v[0] for k, v in urlkit.URL_RULES.items()})
    rows_ = []
    for f, wv in zip(fusion.MSG_FEATURES, w_m):
        rows_.append({"feature": f, "fitted": round(float(wv), 3), "prior": prior.get(f)})
    json.dump(rows_, open(os.path.join(ROOT, "results", "fusion_weights.json"), "w"), indent=1)
    print("saved models/fusion.json")
    big = sorted(rows_, key=lambda r: -abs(r["fitted"]))[:14]
    print("largest fitted weights:", [(r["feature"], r["fitted"]) for r in big])


if __name__ == "__main__":
    main()
