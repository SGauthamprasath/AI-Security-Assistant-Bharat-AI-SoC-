"""Text normalisation + feature hashing for SMS / message text.

Design goals
------------
1. *Remove dataset artefacts.*  The public smishing corpus we train on is anonymised
   (it contains tokens like ``<URL>`` / ``<PHONE_NUMBER>``) while legitimate messages
   contain real URLs and numbers.  If we left that difference in, the classifier would
   learn "has a placeholder => scam" and look brilliant on paper but fail on a phone.
   ``normalize_sms`` maps BOTH worlds onto the same neutral tokens
   (``urltok``, ``phonetok``, ``numtok``, ``amttok``, ``datetok``).
2. *Be trivially portable.*  Features are hashed with CRC-32 (zlib / java.util.zip.CRC32) into a fixed
   2**18 space and the model is a single linear layer, so a Kotlin / C++ port is
   ~40 lines.  Python (training) and any port MUST produce identical indices.
"""
from __future__ import annotations

import math
import re
import unicodedata
from zlib import crc32
from typing import Iterable, List, Tuple

HASH_DIM = 1 << 18  # 262,144 feature slots

# --------------------------------------------------------------------------- URLs
_TLDS = (
    "com|in|net|org|co|io|me|ly|gl|to|cc|app|xyz|top|info|biz|online|site|club|live|link|"
    "click|shop|store|cn|ru|tk|ml|ga|cf|gq|us|uk|pw|ws|vip|work|support|help|icu|buzz|cyou|"
    "sbs|life|page|dev|cloud|tech|id|bd|pk|lk|np|ae|sa|nl|de|fr|es|it|br|mx|au|ca|sg|my|ph"
)
URL_RE = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s<>\"'​]+"
    r"|\b(?:[a-z0-9][a-z0-9\-]{0,62}\.)+(?:" + _TLDS + r")\b(?:/[^\s<>\"'​]*)?",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_TRAIL = ".,;:!?)]}>'\""


def extract_urls(text: str) -> List[str]:
    """Return URL-looking substrings (trailing punctuation stripped, e-mail domains skipped)."""
    out: List[str] = []
    emails = [m.span() for m in EMAIL_RE.finditer(text)]
    for m in URL_RE.finditer(text):
        s, e = m.span()
        if any(a <= s < b for a, b in emails):
            continue  # bare domain inside an e-mail address
        u = m.group(0).rstrip(_TRAIL)
        if len(u) >= 4 and u not in out:
            out.append(u)
    return out


# --------------------------------------------------------------------------- normalisation
_PH = [
    (re.compile(r"<\s*url\s*>", re.I), " urltok "),
    (re.compile(r"<\s*phone_number\s*>", re.I), " phonetok "),
    (re.compile(r"<\s*email_address\s*>", re.I), " emailtok "),
    (re.compile(r"<\s*date_time\s*>", re.I), " datetok "),
    (re.compile(r"<\s*[A-Z][A-Z_ ]{1,40}\s*>"), " numtok "),  # other anonymiser placeholders
]
_AMT = re.compile(r"(?:rs\.?|inr|₹|usd|\$|£|eur|€)\s*\d[\d,\.]*|\d[\d,\.]*\s*(?:rs\b|/-|inr\b)", re.I)
_PHONE = re.compile(r"(?<![\w])(?:\+?91[\s\-]?)?[6-9]\d{9}(?!\d)|(?<![\w])\+?\d[\d\s\-]{9,15}\d(?!\d)")
_DATE = re.compile(r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b|\b\d{1,2}:\d{2}(?::\d{2})?\s*(?:am|pm)?\b|\b\d{1,2}(?:st|nd|rd|th)?[\s\-](?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[\s\-,]*\d{0,4}\b", re.I)
_DIGITS = re.compile(r"\d{4,}")
_MASK = re.compile(r"\b(?:xx+|x{2,}\d+|\*{2,}\d+)\b", re.I)


def normalize_sms(text: str) -> str:
    t = unicodedata.normalize("NFKC", str(text))
    for rx, rep in _PH:
        t = rx.sub(rep, t)
    t = EMAIL_RE.sub(" emailtok ", t)
    t = URL_RE.sub(" urltok ", t)
    t = t.lower()
    t = _AMT.sub(" amttok ", t)
    t = _DATE.sub(" datetok ", t)
    t = _PHONE.sub(" phonetok ", t)
    t = _MASK.sub(" numtok ", t)
    t = _DIGITS.sub(" numtok ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def skeleton(text: str, n_words: int = 10) -> str:
    """Near-duplicate key used to *group* messages so templated spam never straddles train/test."""
    t = re.sub(r"[^a-zऀ-ॿ ]+", " ", normalize_sms(text))
    return " ".join(t.split()[:n_words])


# --------------------------------------------------------------------------- hashing
def fnv1a32(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


_WORD_RE = re.compile(r"[a-z0-9ऀ-ॿ']+")


def text_features(norm: str, extras: Iterable[str] = (), dim: int = HASH_DIM) -> Tuple[List[int], float]:
    """Hashed binary features -> (sorted unique indices, value-per-feature = 1/sqrt(n)).

    word 1-grams, word 2-grams and character 3-5-grams (word-bounded) + extra tokens.
    """
    words = _WORD_RE.findall(norm)
    toks: set = set()
    for w in words:
        toks.add("w:" + w)
        pw = f"^{w}$"
        for n in (3, 4, 5):
            for i in range(len(pw) - n + 1):
                toks.add("c:" + pw[i : i + n])
    for a, b in zip(words, words[1:]):
        toks.add("b:" + a + "_" + b)
    for x in extras:
        toks.add("x:" + x)
    idx = sorted({crc32(t.encode("utf-8")) % dim for t in toks})
    val = 1.0 / math.sqrt(len(idx)) if idx else 0.0
    return idx, val


def meta_tokens(raw: str) -> List[str]:
    """Style tokens computed on the RAW text (case / punctuation survive here)."""
    n = max(len(raw), 1)
    up = sum(c.isupper() for c in raw) / n
    ex = raw.count("!")
    toks = []
    toks.append("len=%d" % min(len(raw) // 40, 8))
    toks.append("up=%d" % min(int(up * 10), 5))
    toks.append("ex=%d" % min(ex, 3))
    nu = len(extract_urls(raw)) + len(re.findall(r"<\s*url\s*>", raw, re.I))
    toks.append("nurl=%d" % min(nu, 2))
    if re.search(r"[^\x00-\x7f]", raw):
        toks.append("nonascii")
    return toks
