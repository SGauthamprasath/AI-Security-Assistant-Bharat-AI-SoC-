"""URL / host analysis: parsing, registered-domain logic, lexical features and explainable rules.

The *learned* URL model sees only host-level features (see scripts/03_train_url.py for why:
benign training URLs come from a domain ranking and have no paths, so any path feature would be a
dataset shortcut, not a threat signal).  Path / query / scheme / port evidence is handled by
explicit rules whose weights are fitted on the fusion stage (scripts/05_fit_fusion.py).
"""
from __future__ import annotations

import json
import math
import os
import re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(os.path.dirname(HERE), "models")

# --------------------------------------------------------------------------- reference data
SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "t.co", "rb.gy", "t.ly", "bit.do", "shrtco.de", "rebrand.ly",
    "bitly.ws", "goo.gl", "ow.ly", "buff.ly", "tiny.cc", "s.id", "v.gd", "shorturl.at", "l.ead.me", "lnkd.in",
    "tr.ee", "clck.ru", "qr.ae", "u.to", "urlz.fr", "han.gl", "soo.gd", "x.co", "adf.ly", "bl.ink", "short.io",
    "ouo.io", "gg.gg", "2u.pw", "snip.ly", "mcaf.ee", "wa.me",
}
RISKY_TLDS = {
    "xyz", "top", "icu", "buzz", "cyou", "sbs", "click", "link", "work", "support", "vip", "tk", "ml", "ga", "cf",
    "gq", "pw", "cc", "ws", "live", "life", "online", "site", "club", "rest", "monster", "quest", "bond", "lol",
    "shop", "store", "fun", "cam", "lat",
}
KEYWORDS = (
    "login", "signin", "secure", "verify", "verification", "update", "kyc", "bank", "account", "wallet", "pay",
    "claim", "refund", "reward", "bonus", "gift", "prize", "support", "helpdesk", "alert", "suspend", "unlock",
    "confirm", "billing", "invoice", "recover", "official", "customer", "netbanking", "upi", "otp", "free", "offer",
)
# brand -> (match tokens, legitimate registered domains)
BRANDS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "sbi": (("sbi", "onlinesbi", "yonosbi"), ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "yonosbi.com", "sbicard.com", "sbilife.co.in", "sbi.bank.in", "sbi.sbi")),
    "hdfc": (("hdfc", "hdfcbank"), ("hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcbank.net")),
    "icici": (("icici", "icicibank"), ("icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com", "icicipruamc.com", "icici.com")),
    "axis": (("axisbank", "axis"), ("axisbank.com", "axis.bank.in", "axismaxlife.com")),
    "kotak": (("kotak",), ("kotak.com", "kotaklife.com", "kotakmahindrabank.com")),
    "pnb": (("pnbindia", "pnb"), ("pnbindia.in", "pnbcard.com", "netpnb.com")),
    "paytm": (("paytm",), ("paytm.com", "paytmbank.com", "paytmpayments.com", "paytmmoney.com")),
    "phonepe": (("phonepe",), ("phonepe.com",)),
    "gpay": (("gpay", "googlepay"), ("google.com", "gpay.app.goo.gl")),
    "amazon": (("amazon", "amzn"), ("amazon.in", "amazon.com", "amzn.in", "amzn.to", "amazonpay.in", "primevideo.com", "amazon.co.uk", "amazon.de", "amazonaws.com")),
    "flipkart": (("flipkart", "fkrt"), ("flipkart.com", "fkrt.it", "fkrt.cc")),
    "irctc": (("irctc",), ("irctc.co.in", "irctc.com", "irctctourism.com")),
    "epfo": (("epfo", "epfindia"), ("epfindia.gov.in", "epfindia.com")),
    "uidai": (("uidai", "aadhaar", "aadhar"), ("uidai.gov.in", "myaadhaar.uidai.gov.in")),
    "incometax": (("incometax", "incometaxindia", "itreturn"), ("incometax.gov.in", "incometaxindia.gov.in", "incometaxindiaefiling.gov.in")),
    "airtel": (("airtel",), ("airtel.in", "airtel.com", "airtelbank.com", "airtelxstream.in")),
    "jio": (("jio", "myjio"), ("jio.com", "jiopay.com", "jiomart.com", "jiocinema.com")),
    "vi": (("myvi", "vodafone"), ("myvi.in", "vodafone.com", "vodafoneidea.com")),
    "bsnl": (("bsnl",), ("bsnl.co.in",)),
    "indiapost": (("indiapost",), ("indiapost.gov.in", "epostoffice.gov.in")),
    "dhl": (("dhl",), ("dhl.com", "dhl.de")),
    "fedex": (("fedex",), ("fedex.com",)),
    "bluedart": (("bluedart",), ("bluedart.com",)),
    "delhivery": (("delhivery",), ("delhivery.com",)),
    "google": (("google", "gmail"), ("google.com", "google.co.in", "gmail.com", "googleapis.com", "gstatic.com", "youtube.com", "goo.gl", "g.co")),
    "microsoft": (("microsoft", "office365", "outlook"), ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com", "msn.com")),
    "apple": (("apple", "icloud"), ("apple.com", "icloud.com")),
    "netflix": (("netflix",), ("netflix.com",)),
    "whatsapp": (("whatsapp",), ("whatsapp.com", "whatsapp.net", "wa.me")),
    "facebook": (("facebook",), ("facebook.com", "fb.com", "fb.me", "messenger.com")),
    "instagram": (("instagram",), ("instagram.com",)),
    "paypal": (("paypal",), ("paypal.com", "paypal.me")),
    "trai": (("trai",), ("trai.gov.in",)),
    "cowin": (("cowin",), ("cowin.gov.in",)),
    "fastag": (("fastag",), ("npci.org.in", "netc.org.in")),
    "npci": (("npci", "bhim"), ("npci.org.in", "bhimupi.org.in")),
}
_BRAND_TOKENS = sorted({t for toks, _ in BRANDS.values() for t in toks}, key=len, reverse=True)
_OFFICIAL = {d for _, ds in BRANDS.values() for d in ds}
_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


@lru_cache(maxsize=1)
def _psl_multi() -> frozenset:
    p = os.path.join(MODEL_DIR, "psl_multi.json")
    if os.path.exists(p):
        return frozenset(json.load(open(p)))
    return frozenset({"co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "firm.in", "gen.in", "ind.in",
                      "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.br", "com.cn", "co.jp",
                      "co.za", "com.mx", "com.sg", "com.my", "com.pk", "com.bd", "co.id", "co.nz", "com.tr", "com.ng"})


@lru_cache(maxsize=1)
def _shared_hosts() -> frozenset:
    p = os.path.join(MODEL_DIR, "shared_hosting.txt")
    if os.path.exists(p):
        return frozenset(l.strip() for l in open(p) if l.strip())
    return frozenset({"000webhostapp.com", "blogspot.com", "weebly.com", "wixsite.com", "duckdns.org", "workers.dev", "web.app",
                      "firebaseapp.com", "github.io", "netlify.app", "vercel.app", "pages.dev", "herokuapp.com", "glitch.me"})


@lru_cache(maxsize=1)
def _trusted() -> frozenset:
    p = os.path.join(MODEL_DIR, "trusted_domains.txt")
    if os.path.exists(p):
        return frozenset(l.strip() for l in open(p) if l.strip())
    return frozenset()


@lru_cache(maxsize=1)
def _tld_rate() -> Tuple[Dict[str, float], float]:
    p = os.path.join(MODEL_DIR, "tld_rate.json")
    if os.path.exists(p):
        d = json.load(open(p))
        return d["rate"], d["default"]
    return {}, 0.5


def reload_reference_data() -> None:
    for f in (_psl_multi, _shared_hosts, _trusted, _tld_rate):
        f.cache_clear()


# --------------------------------------------------------------------------- parsing
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IP_ALT = re.compile(r"^(?:0x[0-9a-f]+|\d{8,10})$", re.I)


def parse_url(url: str) -> Dict[str, object]:
    u = url.strip().strip("<>\"'")
    has_scheme = re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I) is not None
    s = u if has_scheme else "http://" + u
    try:
        sp = urlsplit(s)
        host = (sp.hostname or "").lower().rstrip(".")
        port = sp.port
    except ValueError:
        host, port, sp = "", None, urlsplit("http://invalid")
    userinfo = "@" in (sp.netloc or "")
    return {
        "raw": url, "scheme": sp.scheme.lower() if has_scheme else "", "host": host, "port": port,
        "path": sp.path or "", "query": sp.query or "", "userinfo": userinfo,
    }


def registered_domain(host: str) -> Tuple[str, str, str]:
    """-> (subdomain, registered_domain, suffix).  IP hosts return ("", host, "")."""
    if not host or _IPV4.match(host) or _IP_ALT.match(host):
        return "", host, ""
    labels = host.split(".")
    if len(labels) == 1:
        return "", host, ""
    multi = _psl_multi()
    suffix_len = 1
    if len(labels) >= 3 and ".".join(labels[-2:]) in multi:
        suffix_len = 2
    if len(labels) >= 2 and ".".join(labels[-2:]) in multi:
        suffix_len = 2
    if len(labels) <= suffix_len:
        return "", host, ".".join(labels[-suffix_len:])
    reg = ".".join(labels[-(suffix_len + 1):])
    sub = ".".join(labels[: -(suffix_len + 1)])
    return sub, reg, ".".join(labels[-suffix_len:])


# --------------------------------------------------------------------------- features
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c: Dict[str, int] = {}
    for ch in s:
        c[ch] = c.get(ch, 0) + 1
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]



def _deletes(w: str, d: int) -> set:
    out = {w}
    for _ in range(d):
        out = {x[:i] + x[i + 1:] for x in out for i in range(len(x))}
    return out - {w} if d == 1 else out


@lru_cache(maxsize=1)
def _deletion_index():
    idx1: Dict[str, set] = {}
    idx2: Dict[str, set] = {}
    for t in _BRAND_TOKENS:
        if len(t) >= 5:
            for v in _deletes(t, 1) | {t}:
                idx1.setdefault(v, set()).add(t)
        if len(t) >= 8:
            for v in _deletes(t, 2) | _deletes(t, 1) | {t}:
                idx2.setdefault(v, set()).add(t)
    return idx1, idx2


def _pieces(s: str) -> List[str]:
    return [p for p in re.split(r"[^a-z0-9]+", s) if p]


def _match_brand(text: str) -> Optional[str]:
    """Long brand tokens match as substrings; short ones (sbi, jio, axis...) only as whole pieces."""
    pcs = set(_pieces(text))
    for t in _BRAND_TOKENS:
        if (len(t) >= 5 and t in text) or t in pcs:
            return t
    return None


def brand_analysis(host: str) -> Dict[str, object]:
    sub, reg, suf = registered_domain(host)
    reg_label = reg.split(".")[0] if "." in reg else reg
    official = reg in _OFFICIAL
    out = {"brand_in_sub": None, "brand_in_reg": None, "typosquat": None, "typosquat_dist": 9, "official": official}
    if official:
        return out
    sub_d = (sub or "").translate(_HOMO)
    reg_d = reg_label.translate(_HOMO)
    if sub_d:
        out["brand_in_sub"] = _match_brand(sub_d)
    out["brand_in_reg"] = _match_brand(reg_d)
    # typosquat: registered label (de-leeted, hyphen-split pieces) within edit distance 1 (any brand >=5 chars)
    # or 2 (brands >=8 chars) - candidates come from a deletion index (SymSpell idea), then verified exactly.
    best, best_t = 9, None
    idx1, idx2 = _deletion_index()
    for piece in [reg_d] + [p for p in _pieces(reg_d) if len(p) >= 5]:
        if len(piece) < 4 or len(piece) > 30:
            continue
        cands = set()
        for v in _deletes(piece, 1) | {piece}:
            cands |= idx1.get(v, set())
        for t in cands:
            if t != piece and t not in piece and abs(len(piece) - len(t)) <= 1 and _edit_distance(piece, t, cap=1) == 1:
                if 1 < best or best == 9:
                    best, best_t = 1, t
        if best == 9 and len(piece) >= 7:
            c2 = set()
            for v in _deletes(piece, 2) | _deletes(piece, 1) | {piece}:
                c2 |= idx2.get(v, set())
            for t in c2:
                if t != piece and t not in piece and _edit_distance(piece, t, cap=2) == 2:
                    best, best_t = 2, t
    if best <= 2:
        out["typosquat"], out["typosquat_dist"] = best_t, best
    return out


FEATURE_NAMES = [
    "host_len", "n_labels", "n_sub_labels", "reg_label_len", "n_dots", "n_hyphens", "n_digits", "digit_ratio",
    "longest_digit_run", "entropy_host", "entropy_reg", "vowel_ratio_reg", "max_consonant_run", "is_ip", "has_punycode",
    "has_nonascii", "tld_phish_rate", "tld_len", "is_shortener", "is_shared_host", "n_keywords", "brand_in_sub",
    "brand_in_reg_unofficial", "typosquat_dist", "n_hyphen_reg", "digit_ratio_reg", "mean_label_len", "max_label_len",
    "risky_tld", "sub_depth_gt3",
]


def host_features(host: str) -> np.ndarray:
    host = host.lower()
    sub, reg, suf = registered_domain(host)
    labels = host.split(".") if host else [""]
    reg_label = reg.split(".")[0] if reg and "." in reg else reg
    is_ip = 1.0 if (_IPV4.match(host) or _IP_ALT.match(host)) else 0.0
    digits = sum(c.isdigit() for c in host)
    run = max((len(m) for m in re.findall(r"\d+", host)), default=0)
    vow = sum(c in "aeiou" for c in reg_label) / max(len(reg_label), 1)
    cons_run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", reg_label)), default=0)
    tld = suf.split(".")[-1] if suf else ""
    rate, default = _tld_rate()
    ba = brand_analysis(host)
    n_kw = sum(k in host for k in KEYWORDS)
    f = [
        len(host), len(labels), len(sub.split(".")) if sub else 0, len(reg_label), host.count("."), host.count("-"), digits,
        digits / max(len(host), 1), run, _entropy(host), _entropy(reg_label), vow, cons_run, is_ip,
        1.0 if "xn--" in host else 0.0, 1.0 if any(ord(c) > 127 for c in host) else 0.0, rate.get(tld, default), len(tld),
        1.0 if reg in SHORTENERS else 0.0, 1.0 if reg in _shared_hosts() else 0.0, n_kw,
        1.0 if ba["brand_in_sub"] else 0.0,
        1.0 if (ba["brand_in_reg"] and not ba["official"]) else 0.0, float(ba["typosquat_dist"]),
        reg_label.count("-"), sum(c.isdigit() for c in reg_label) / max(len(reg_label), 1),
        sum(len(l) for l in labels) / max(len(labels), 1), max(len(l) for l in labels),
        1.0 if tld in RISKY_TLDS else 0.0, 1.0 if (sub and len(sub.split(".")) > 3) else 0.0,
    ]
    return np.asarray(f, dtype=np.float64)


# --------------------------------------------------------------------------- rules
# id: (default weight in log-odds, plain-language description, remediation ids)
URL_RULES: Dict[str, Tuple[float, str, Tuple[str, ...]]] = {
    "U_IP_HOST": (1.8, "The link goes to a raw IP address instead of a normal website name.", ("DONT_OPEN_LINK",)),
    "U_PUNYCODE": (1.6, "The website name uses look-alike international characters that can imitate a real brand.", ("DONT_OPEN_LINK",)),
    "U_USERINFO": (1.5, "The link contains an '@' trick that hides the real destination.", ("DONT_OPEN_LINK",)),
    "U_SHORTENER": (0.8, "The link is shortened, so you cannot see where it really leads.", ("VERIFY_OFFICIAL_CHANNEL",)),
    "U_BRAND_IMPERSONATION": (2.4, "The website name contains a well-known brand but is NOT that brand's official website.", ("DONT_OPEN_LINK", "VERIFY_OFFICIAL_CHANNEL", "REPORT_1930")),
    "U_BRAND_IN_SUBDOMAIN": (2.2, "A bank/brand name is placed in front of an unrelated domain to look genuine.", ("DONT_OPEN_LINK", "REPORT_1930")),
    "U_TYPOSQUAT": (2.2, "The website name is a slightly misspelt copy of a well-known brand.", ("DONT_OPEN_LINK", "REPORT_1930")),
    "U_RISKY_TLD": (0.6, "The website ends in a domain type that is frequently abused for scams.", ()),
    "U_SHARED_HOSTING": (0.7, "The page is on a free hosting service that scammers often abuse.", ()),
    "U_MANY_KEYWORDS": (0.9, "The website name stuffs in words like 'secure', 'verify', 'kyc' or 'login'.", ("DONT_OPEN_LINK",)),
    "U_NONSTD_PORT": (0.9, "The link uses an unusual network port, which genuine sites rarely do.", ()),
    "U_HTTP_ONLY": (0.3, "The link is not encrypted (http, not https).", ()),
    "U_APK_DOWNLOAD": (2.6, "The link downloads an app/installer file (.apk/.exe), a common way to install malware.", ("DONT_INSTALL_APK", "REPORT_1930")),
    "U_LOGIN_PATH": (0.7, "The link points to a login / verification page.", ("NEVER_SHARE_CREDENTIALS",)),
    "U_REDIRECT_IN_QUERY": (1.2, "The link contains another web address inside it, a redirect trick.", ("DONT_OPEN_LINK",)),
    "U_RANDOM_PATH": (0.5, "The link has a long random-looking path, typical of one-time scam pages.", ()),
    "U_DEEP_SUBDOMAIN": (0.6, "The website name has an unusually long chain of sub-parts.", ()),
    "U_TRUSTED_DOMAIN": (-2.2, "The website is a well-known, widely used domain and shows no impersonation signs.", ()),
    "U_OFFICIAL_BRAND": (-2.6, "The website is the brand's official domain.", ()),
    "U_GOV_EDU": (-1.2, "The website belongs to a government or educational domain.", ()),
}
_PATH_LOGIN = re.compile(r"(log-?in|sign-?in|verify|verification|kyc|update|secure|account|auth|wallet|claim|refund|reward|otp|banking)", re.I)
_APK = re.compile(r"\.(apk|exe|scr|msi|bat|jar|dmg)(?:$|[?#])", re.I)
_HEXLIKE = re.compile(r"[A-Za-z0-9_\-]{24,}")


def url_rule_hits(url: str) -> List[Tuple[str, str]]:
    """Return [(rule_id, matched_detail)] for one URL."""
    p = parse_url(url)
    host = str(p["host"])
    if not host:
        return []
    hits: List[Tuple[str, str]] = []
    sub, reg, suf = registered_domain(host)
    tld = suf.split(".")[-1] if suf else ""
    ba = brand_analysis(host)
    is_ip = bool(_IPV4.match(host) or _IP_ALT.match(host))
    if is_ip:
        hits.append(("U_IP_HOST", host))
    if "xn--" in host:
        hits.append(("U_PUNYCODE", host))
    if p["userinfo"]:
        hits.append(("U_USERINFO", "@ in address"))
    if reg in SHORTENERS:
        hits.append(("U_SHORTENER", reg))
    if ba["brand_in_reg"] and not ba["official"]:
        hits.append(("U_BRAND_IMPERSONATION", f"'{ba['brand_in_reg']}' in {reg}"))
    if ba["brand_in_sub"] and not ba["official"]:
        hits.append(("U_BRAND_IN_SUBDOMAIN", f"'{ba['brand_in_sub']}' before {reg}"))
    if ba["typosquat"]:
        hits.append(("U_TYPOSQUAT", f"{reg} ~ {ba['typosquat']}"))
    if tld in RISKY_TLDS:
        hits.append(("U_RISKY_TLD", "." + tld))
    if reg in _shared_hosts():
        hits.append(("U_SHARED_HOSTING", reg))
    if sum(k in host for k in KEYWORDS) >= 2:
        hits.append(("U_MANY_KEYWORDS", ",".join(k for k in KEYWORDS if k in host)[:60]))
    if p["port"] and p["port"] not in (80, 443):
        hits.append(("U_NONSTD_PORT", str(p["port"])))
    if p["scheme"] == "http":
        hits.append(("U_HTTP_ONLY", "http"))
    path_q = str(p["path"]) + ("?" + str(p["query"]) if p["query"] else "")
    if _APK.search(path_q):
        hits.append(("U_APK_DOWNLOAD", path_q[-40:]))
    if _PATH_LOGIN.search(path_q) and not ba["official"]:
        hits.append(("U_LOGIN_PATH", _PATH_LOGIN.search(path_q).group(0)))
    if re.search(r"https?(?::|%3a)(?:/|%2f){2}", str(p["query"]) + str(p["path"]), re.I):
        hits.append(("U_REDIRECT_IN_QUERY", "url inside url"))
    if _HEXLIKE.search(str(p["path"])) and re.search(r"\d", _HEXLIKE.search(str(p["path"])).group(0)):
        hits.append(("U_RANDOM_PATH", "long token"))
    if sub and len(sub.split(".")) > 3:
        hits.append(("U_DEEP_SUBDOMAIN", sub))
    # trust (only if no impersonation / shared hosting / ip evidence)
    bad = {"U_IP_HOST", "U_PUNYCODE", "U_USERINFO", "U_BRAND_IMPERSONATION", "U_BRAND_IN_SUBDOMAIN", "U_TYPOSQUAT", "U_SHARED_HOSTING", "U_APK_DOWNLOAD"}
    if not any(h[0] in bad for h in hits):
        if ba["official"]:
            hits.append(("U_OFFICIAL_BRAND", reg))
        elif reg in _trusted() and reg not in SHORTENERS:
            hits.append(("U_TRUSTED_DOMAIN", reg))
        if suf.endswith(("gov.in", "nic.in", "ac.in", "edu", "gov", "edu.in")) or reg.endswith((".gov.in", ".nic.in", ".ac.in", ".edu")):
            hits.append(("U_GOV_EDU", suf))
    return hits


def url_model_logit_features(url: str) -> np.ndarray:
    return host_features(str(parse_url(url)["host"]))
