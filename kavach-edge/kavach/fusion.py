"""Risk fusion: combine ML scores and explainable rules into one calibrated risk + SAFE/SUSPICIOUS/DANGEROUS band.

The combiner is a *constrained logistic regression* ("stacker"):

      logit(risk) = b + w_s * z_sms + w_u * z_url_max + c * has_url + sum_r w_r * hit_r

* z_sms / z_url are the calibrated log-odds from the two ML models.
* hit_r are rule indicators; each rule's weight is **sign-constrained** (scam rules >= 0, legitimate-
  looking rules <= 0, trust rules <= 0) and regularised towards a hand-set prior, so the fit can never
  flip the meaning of a rule - it can only decide how much to trust it.  That keeps every verdict
  explainable: the evidence JSON lists exactly which terms moved the score and by how much.
* Thresholds are then picked on validation data to hit a target false-alarm rate (not accuracy).
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Sequence, Tuple

import numpy as np

from . import sms_rules, urlkit

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

SMS_RULE_IDS: List[str] = sms_rules.rule_ids()
URL_RULE_IDS: List[str] = list(urlkit.URL_RULES.keys())
URL_TRUST_IDS = {"U_TRUSTED_DOMAIN", "U_OFFICIAL_BRAND", "U_GOV_EDU"}
MSG_FEATURES: List[str] = ["z_sms", "z_url", "has_url"] + SMS_RULE_IDS + URL_RULE_IDS
URL_FEATURES: List[str] = ["z_url"] + URL_RULE_IDS


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -40, 40)))


def aggregate_url_hits(per_url_hits: Sequence[Sequence[str]]) -> Dict[str, float]:
    """Risk rules fire if ANY url has them; trust rules only if ALL urls have them (worst-case wins)."""
    if not per_url_hits:
        return {}
    out: Dict[str, float] = {}
    for rid in URL_RULE_IDS:
        flags = [rid in h for h in per_url_hits]
        out[rid] = float(all(flags) if rid in URL_TRUST_IDS else any(flags))
    return out


def message_vector(z_sms: float, url_z: Sequence[float], sms_hit_ids: Sequence[str], per_url_hits: Sequence[Sequence[str]]) -> np.ndarray:
    v = np.zeros(len(MSG_FEATURES))
    v[0] = z_sms
    if url_z:
        v[1] = max(url_z)
        v[2] = 1.0
    hs = set(sms_hit_ids)
    for i, rid in enumerate(SMS_RULE_IDS):
        v[3 + i] = 1.0 if rid in hs else 0.0
    agg = aggregate_url_hits(per_url_hits)
    off = 3 + len(SMS_RULE_IDS)
    for i, rid in enumerate(URL_RULE_IDS):
        v[off + i] = agg.get(rid, 0.0)
    return v


def url_vector(z_url: float, hit_ids: Sequence[str]) -> np.ndarray:
    v = np.zeros(len(URL_FEATURES))
    v[0] = z_url
    hs = set(hit_ids)
    for i, rid in enumerate(URL_RULE_IDS):
        v[1 + i] = 1.0 if rid in hs else 0.0
    return v


# --------------------------------------------------------------------------- fitting
def priors_and_bounds(features: Sequence[str]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    sp = sms_rules.prior_weights()
    up = {k: v[0] for k, v in urlkit.URL_RULES.items()}
    w0, lo, hi = [], [], []
    for f in features:
        if f == "z_sms":
            w0.append(1.0); lo.append(0.3); hi.append(1.6)
        elif f == "z_url":
            w0.append(0.6); lo.append(0.0); hi.append(1.6)
        elif f == "has_url":
            w0.append(0.0); lo.append(-1.0); hi.append(1.0)
        elif f in sp:
            p = sp[f]
            w0.append(p); lo.append(0.0 if p >= 0 else -3.0); hi.append(3.0 if p >= 0 else 0.0)
        elif f in up:
            p = up[f]
            w0.append(p); lo.append(0.0 if p >= 0 else -3.0); hi.append(3.0 if p >= 0 else 0.0)
        else:
            raise KeyError(f)
    return np.array(w0), np.array(lo), np.array(hi)


def fit_constrained_lr(X: np.ndarray, y: np.ndarray, features: Sequence[str], sample_weight: np.ndarray | None = None,
                       lam: float = 30.0) -> Tuple[np.ndarray, float]:
    """Minimise weighted logloss + (lam/N) * ||w - w0||^2 subject to sign bounds (L-BFGS-B). Returns (w, bias)."""
    from scipy.optimize import minimize

    w0, lo, hi = priors_and_bounds(features)
    n, d = X.shape
    sw = np.ones(n) if sample_weight is None else sample_weight
    sw = sw / sw.mean()

    def f(theta):
        w, b = theta[:d], theta[d]
        z = X @ w + b
        p = sigmoid(z)
        eps = 1e-12
        ll = -(sw * (y * np.log(p + eps) + (1 - y) * np.log(1 - p + eps))).mean()
        reg = lam / n * np.sum((w - w0) ** 2)
        g_z = sw * (p - y) / n
        gw = X.T @ g_z + 2 * lam / n * (w - w0)
        gb = g_z.sum()
        return ll + reg, np.r_[gw, gb]

    bounds = [(l, h) for l, h in zip(lo, hi)] + [(-8, 8)]
    res = minimize(f, np.r_[w0, 0.0], jac=True, method="L-BFGS-B", bounds=bounds, options={"maxiter": 500})
    return res.x[:d], float(res.x[d])


def threshold_at_fpr(scores: np.ndarray, y: np.ndarray, fpr: float) -> float:
    """Smallest threshold whose false-positive rate on the negatives is <= fpr."""
    neg = np.sort(scores[y == 0])
    if len(neg) == 0:
        return 0.5
    k = int(np.floor(len(neg) * (1 - fpr)))
    k = min(max(k, 0), len(neg) - 1)
    return float(neg[k]) + 1e-9


# --------------------------------------------------------------------------- runtime
class Fusion:
    def __init__(self, path: str | None = None):
        self.path = path or os.path.join(MODEL_DIR, "fusion.json")
        d = json.load(open(self.path))
        self.d = d
        self.msg_w = np.array([d["message"]["weights"][f] for f in MSG_FEATURES])
        self.msg_b = d["message"]["bias"]
        self.url_w = np.array([d["url"]["weights"][f] for f in URL_FEATURES])
        self.url_b = d["url"]["bias"]
        self.net = d["network"]
        self.th = d["thresholds"]

    def message_logit(self, v: np.ndarray) -> float:
        return float(v @ self.msg_w + self.msg_b)

    def url_logit(self, v: np.ndarray) -> float:
        return float(v @ self.url_w + self.url_b)

    def band(self, p: float, kind: str = "message") -> str:
        t = self.th[kind]
        return "dangerous" if p >= t["dangerous"] else ("suspicious" if p >= t["suspicious"] else "safe")

    def contributions(self, v: np.ndarray, kind: str = "message") -> List[Tuple[str, float]]:
        names, w = (MSG_FEATURES, self.msg_w) if kind == "message" else (URL_FEATURES, self.url_w)
        return [(n, float(x * wi)) for n, x, wi in zip(names, v, w) if x != 0 and wi != 0]
