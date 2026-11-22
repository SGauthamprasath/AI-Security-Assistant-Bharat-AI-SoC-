#!/usr/bin/env python3
"""Step 1 - assemble leak-resistant training / validation / test data.

Inputs (data/raw, fetched by data/fetch_data.py - public sources only):
  smishing_imc25.csv        real user-reported smishing (IMC'25, CC-BY-4.0), India-heavy
  sms_uci.tsv               UCI SMS Spam Collection (mirror)
  phishing_links_active.txt Phishing.Database (live phishing URL feed)
  tranco_top1m.csv          Tranco top-1M domain ranking (benign hosts)
Outputs (data/processed):
  sms_all.csv     text,label,source,split
  url_hosts.csv   host,label,source,split
and in models/: psl_multi-aware helper lists
  shared_hosting.txt  (registered domains abused by many phishing hosts - derived from the feed)
  trusted_domains.txt (top-50k popular registered domains, minus shorteners / shared hosts)
  tld_rate.json       (phish rate per TLD, computed on the TRAIN split only)

Leakage controls (what makes the numbers trustworthy):
  * SMS: split by *skeleton group* (templated scams never straddle train/test) + cap per skeleton
  * URL: split by registered domain (shared-hosting platforms split by host)
  * TLD statistics come from the train split only
"""
import collections
import json
import os
import random
import sys

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import sms_rules, textnorm, urlkit  # noqa: E402
from data.legit_templates import gen  # noqa: E402

RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(ROOT, "data", "processed")
MODELS = os.path.join(ROOT, "models")
os.makedirs(OUT, exist_ok=True)
rng = random.Random(1337)


def split_of(key: str) -> str:
    h = textnorm.fnv1a32("split|" + key) % 100
    return "train" if h < 70 else ("val" if h < 85 else "test")


# ======================================================================= SMS
WEAK = {"S_GENERIC_GREETING", "S_URGENCY", "S_CALL_BACK", "S_CLICK_LINK"}


def keep_positive(text: str, scam_type: str) -> bool:
    """Label-noise filter for the *user-reported* corpus.

    IMC'25 labels every REPORTED message as smishing, but people also report genuine OTPs and bank
    notifications.  Left in, those teach the model that a normal OTP/transaction alert is a scam
    (we measured a 46% false-alarm rate on legitimate messages before this filter).  Rule:
      * ambiguous categories (others / telecom / government): keep only if a high-precision scam
        pattern fires,
      * other categories: drop messages that look like a plain notification (OTP / txn alert) with
        no link, no phone number and no scam pattern.
    """
    if scam_type in ("wrong number", "hey mum/dad"):
        return True
    norm = textnorm.normalize_sms(text)
    ids = [h["id"] for h in sms_rules.sms_rule_hits(text, norm)]
    strong = [i for i in ids if i.startswith("S_") and i not in WEAK]
    legit = [i for i in ids if i.startswith("L_")]
    has_hook = "urltok" in norm or "phonetok" in norm
    if scam_type in ("others", "telecom", "government"):
        return bool(strong)
    if legit and not strong and not has_hook:
        return False
    return bool(strong or has_hook or [i for i in ids if i in WEAK])


def build_sms() -> pd.DataFrame:
    rows = []
    d = pd.read_csv(os.path.join(RAW, "smishing_imc25.csv"))
    d = d[d.language.isin(["English", "Hindi"])]
    d = d[d.scam_type.astype(str) != "spam"]
    d = d.dropna(subset=["text"])
    d["text"] = d.text.astype(str).str.strip()
    d = d[d.text.str.len() >= 15]
    n0 = len(d)
    keep = [keep_positive(t, st) for t, st in zip(d.text, d.scam_type)]
    d = d[keep]
    print(f"IMC25 label-noise filter: kept {len(d):,} of {n0:,} reported messages ({len(d)/n0:.0%}); by category:", d.scam_type.value_counts().to_dict())
    cap = collections.Counter()
    for t, lang in zip(d.text, d.language):
        sk = textnorm.skeleton(t)
        if cap[sk] >= 4:
            continue
        cap[sk] += 1
        rows.append((t, 1, "imc25_" + ("hi" if lang == "Hindi" else "en"), split_of("sk|" + sk)))
    u = pd.read_csv(os.path.join(RAW, "sms_uci.tsv"), sep="\t", header=None, names=["y", "t"]).drop_duplicates("t")
    for y, t in zip(u.y, u.t):
        rows.append((t, 1 if y == "spam" else 0, "uci_spam" if y == "spam" else "uci_ham", split_of("sk|" + textnorm.skeleton(t))))
    seen, capl = set(), collections.Counter()
    for t in gen(16000, seed=7):
        if t in seen:
            continue
        seen.add(t)
        sk = textnorm.skeleton(t)
        if capl[sk] >= 30:
            continue
        capl[sk] += 1
        rows.append((t, 0, "legit_synth", split_of("row|" + t)))  # synthetic -> random (row-level) split
    df = pd.DataFrame(rows, columns=["text", "label", "source", "split"])
    return df


# ======================================================================= URL
def build_urls():
    # ---- phishing hosts
    hosts = []
    for line in open(os.path.join(RAW, "phishing_links_active.txt"), errors="ignore"):
        line = line.strip()
        if not line:
            continue
        h = urlkit.parse_url(line)["host"]
        if h and "." in h and len(h) < 120 and all(c.isalnum() or c in ".-_" for c in h):
            hosts.append(h)
    uniq = sorted(set(hosts))
    print(f"phishing: {len(hosts):,} urls -> {len(uniq):,} unique hosts")
    by_reg = collections.defaultdict(list)
    for h in uniq:
        by_reg[urlkit.registered_domain(h)[1]].append(h)
    shared = {r for r, v in by_reg.items() if len(v) >= 40}
    shared |= set(urlkit._shared_hosts())
    shared = {s for s in shared if "." in s and not s.replace(".", "").isdigit()}
    with open(os.path.join(MODELS, "shared_hosting.txt"), "w") as f:
        f.write("\n".join(sorted(shared)) + "\n")
    urlkit.reload_reference_data()
    print(f"shared-hosting registered domains (>=40 phishing hosts): {len(shared)} e.g. {sorted(shared, key=lambda r: -len(by_reg.get(r, [])))[:8]}")
    pos = []
    for r, v in by_reg.items():
        rng.shuffle(v)
        pos += v[: (300 if r in shared else 10)]
    rng.shuffle(pos)
    pos = pos[:140000]

    # ---- benign hosts (Tranco)
    tr = pd.read_csv(os.path.join(RAW, "tranco_top1m.csv"), header=None, names=["rank", "domain"])
    tr["domain"] = tr.domain.astype(str).str.lower().str.strip()
    tr["reg"] = [urlkit.registered_domain(d)[1] for d in tr.domain]
    # trusted list = popular registered domains that are not shorteners / shared hosts
    top = tr[tr["rank"] <= 60000]
    trusted = [r for r in dict.fromkeys(top.reg) if r not in urlkit.SHORTENERS and r not in shared]
    with open(os.path.join(MODELS, "trusted_domains.txt"), "w") as f:
        f.write("\n".join(trusted[:50000]) + "\n")
    print(f"trusted domains: {min(len(trusted), 50000):,}")
    ok = tr[~tr.domain.isin(shared) & ~tr.reg.isin(urlkit.SHORTENERS) & ~tr.reg.isin(shared) & tr.domain.str.contains(r"\.")]
    parts = [ok[ok["rank"] <= 10000].sample(40000 if len(ok[ok["rank"] <= 10000]) > 40000 else len(ok[ok["rank"] <= 10000]), random_state=1),
             ok[(ok["rank"] > 10000) & (ok["rank"] <= 100000)].sample(40000, random_state=2),
             ok[ok["rank"] > 100000].sample(60000, random_state=3)]
    neg = pd.concat(parts)
    prefixes = ["www", "m", "mail", "accounts", "login", "secure", "app", "support", "shop", "my", "portal", "api", "blog", "help", "id", "pay", "web", "cdn", "docs", "store", "online", "netbanking", "services"]
    benign = []
    for d, rk in zip(neg.domain, neg["rank"]):
        if d.count(".") <= 2 and rng.random() < 0.2:
            d = rng.choice(prefixes) + "." + d
        benign.append((d, rk))

    rows = [(h, 1, "phishing_db", np.nan) for h in pos] + [(h, 0, "tranco", rk) for h, rk in benign]
    df = pd.DataFrame(rows, columns=["host", "label", "source", "rank"])
    key = []
    for h in df.host:
        reg = urlkit.registered_domain(h)[1]
        key.append(h if reg in shared else reg)
    df["split"] = [split_of("dom|" + k) for k in key]
    df = df.drop_duplicates("host")
    # TLD phish rate from TRAIN only
    tr_df = df[df.split == "train"].copy()
    tr_df["tld"] = [(urlkit.registered_domain(h)[2] or "").split(".")[-1] for h in tr_df.host]
    g = tr_df.groupby("tld").label.agg(["sum", "count"])
    prior = tr_df.label.mean()
    rate = {t: float((r["sum"] + 5 * prior) / (r["count"] + 5)) for t, r in g.iterrows()}
    json.dump({"rate": rate, "default": float(prior)}, open(os.path.join(MODELS, "tld_rate.json"), "w"))
    urlkit.reload_reference_data()
    return df


if __name__ == "__main__":
    sms = build_sms()
    sms.to_csv(os.path.join(OUT, "sms_all.csv"), index=False)
    print("SMS rows by source/split:")
    print(sms.groupby(["source", "split"]).size().unstack(fill_value=0))
    print("label balance:", sms.groupby(["split", "label"]).size().unstack(fill_value=0).to_dict("index"))
    u = build_urls()
    u.to_csv(os.path.join(OUT, "url_hosts.csv"), index=False)
    print("URL rows:", u.groupby(["split", "label"]).size().unstack(fill_value=0).to_dict("index"))
