"""Thin bridge between the Android app (Kotlin) and the unchanged detector in kavach/.

Flow for one message (Kotlin drives it, Python owns every decision):
    prepare_message(text, sender) -> evidence + verdict + Llama prompt + template fallback   [Python]
    LlmModule.generate(prompt)    -> streamed tokens                                         [Kotlin]
    finalize(llm_text, evidence)  -> checked Llama text, or the template if a check fails    [Python]

The verdict always comes from the detector's risk fusion. Llama only words the explanation.
Kotlin gets plain JSON strings back, so no Python objects cross the language boundary.
"""
from __future__ import annotations

import json
import os
import platform
import re
import time

from kavach import advisor

_DETECTOR = None

# Every file the detector reads. urlkit silently skips missing list files (os.path.exists), which
# would quietly change results, so we check they are really on disk before trusting any output.
_REQUIRED = ["fusion.json", "psl_multi.json", "shared_hosting.txt", "sms_lr.bin", "sms_lr.json",
             "tld_rate.json", "trusted_domains.txt", "url_hgb.json", "url_hgb.npz", "url_ngram.bin"]

MAX_NEW_TOKENS = 96           # 2-3 sentences fit in ~60 tokens; this is the hard cap (~10 s at ~9-12 tok/s)


# ----------------------------------------------------------------------------------- detector
def _model_dir() -> str:
    from kavach import urlkit
    return urlkit.MODEL_DIR


def _detector():
    """Load the detector once and reuse it."""
    global _DETECTOR
    if _DETECTOR is None:
        missing = [f for f in _REQUIRED if not os.path.exists(os.path.join(_model_dir(), f))]
        if missing:
            raise RuntimeError(f"model files missing in {_model_dir()}: {missing}")
        from kavach.pipeline import Detector
        _DETECTOR = Detector(load_net=False)   # SMS + URL only; the network model is not used on the phone
    return _DETECTOR


def _dumps(obj) -> str:
    # default=float turns stray NumPy scalars into plain numbers so json never fails
    return json.dumps(obj, ensure_ascii=False, default=float)


# ----------------------------------------------------------------------------------- prompt
def llama3_chat(system: str, user: str) -> str:
    """Wrap the advisor's system/user prompt in the Llama 3 chat format.

    Same layout ExecuTorch's LlamaDemo uses for model type LLAMA_3 (header line, then the text,
    then <|eot_id|>), ending with an open assistant header so the model writes the answer.
    The SMS text itself is never in the prompt: advisor.build_explain_prompt only passes detector facts.
    """
    return ("<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + system + "<|eot_id|>"
            "<|start_header_id|>user<|end_header_id|>\n\n" + user + "<|eot_id|>"
            "<|start_header_id|>assistant<|end_header_id|>\n\n")


def _package(ev: dict, language: str) -> str:
    """Everything the UI needs before Llama runs."""
    # Narrow prompt: Llama only explains the reasons; the steps come from the playbook (see finalize).
    p = advisor.build_explain_prompt(ev, language)
    v = ev["verdict"]
    return _dumps({
        "verdict": v,                                             # from risk fusion, never from Llama
        "headline": advisor.BAND_TEXT[v["label"]]["en" if language not in ("en", "hi") else language],
        "category_text": ev.get("category_text"),
        "prompt": llama3_chat(p["system"], p["user"]),
        "max_new_tokens": MAX_NEW_TOKENS,
        "fallback": advisor.template_explanation(ev, language),   # shown if Llama is absent or fails a check
        "evidence": ev,                                           # handed back to finalize() unchanged
    })


def prepare_message(text: str, sender: str | None = None, language: str = "en") -> str:
    return _package(_detector().analyze_message(text, sender=sender or None, language=language), language)


def prepare_url(url: str, language: str = "en") -> str:
    return _package(_detector().analyze_url(url, language=language), language)


# ----------------------------------------------------------------------------------- output checks
_SPECIAL = re.compile(r"<\|[a-z_]+\|>")
# Phrases that would contradict a dangerous/suspicious verdict. Llama must never overrule fusion.
_SAYS_SAFE = re.compile(r"\b(?:is|looks|seems|appears)\s+(?:to\s+be\s+)?(?:like\s+)?(?:an?\s+)?(?:safe|genuine|legitimate|"
                        r"real|harmless|official|verified|trusted)\b"
                        r"|\bnot\s+(?:a\s+)?(?:scam|fraud)\b|\bnothing\s+to\s+worry\b|\bverified\s+by\b", re.I)
# Phrases that would contradict a SAFE verdict ("no signs of a scam" is fine, "likely a scam" is not).
_SAYS_SCAM = re.compile(r"\b(?:is|looks|seems|appears|likely|probably|may\s+be|might\s+be|could\s+be)\s+"
                        r"(?:to\s+be\s+|like\s+)?(?:a\s+)?(?:scam|fraud|phishing|dangerous|suspicious|fake)\b", re.I)
# Llama must never SEND the user to a link or number ("visit sbi-help-desk.com", "call 1800..."), even one
# that is in the evidence: a domain planted in the SMS is in the evidence as a *suspicious* domain.
# Negated forms ("do not call", "don't visit", "never open") are allowed.
_DIRECTS = re.compile(
    r"(?<!not )(?<!n't )(?<!never )\b(?:visit|go\s+to|open|click|tap|log\s*in|sign\s*in|contact|call|dial|ring|"
    r"whatsapp|message|text|reach)\b[^.\n]{0,40}?(?:" + advisor._URL.pattern + "|" + advisor._PHONE.pattern + ")",
    re.I)
# "You have been scammed / hacked / lost money": a claim about the user, not about the message.
_HARM_DONE = re.compile(r"\byou\s+(?:have\s+been|have|were|got|'ve\s+been)\s+(?:already\s+)?"
                        r"(?:scammed|hacked|cheated|defrauded|robbed|lost)\b", re.I)
# For a SUSPICIOUS verdict: "likely / very likely / most likely / probably a scam" says more than fusion did.
_LIKELY_SCAM = re.compile(r"\b(?:likely|probably)\s+(?:to\s+be\s+)?(?:a\s+)?(?:scam|fraud|phishing)\b", re.I)
# "100%", "definitely", or a flat "this is a scam" (the detector only says "very likely").
_OVERCLAIM = re.compile(r"\b100\s*%|\b(?:always\s+(?:right|correct)|definitely|certainly|guaranteed)\b"
                        r"|\b(?:is|are)\s+(?:a\s+)?(?:scam|fraud)\b", re.I)
# Lead-ins that echo our prompt, e.g. "Here are the FACTS explained in simple English:"
_PREAMBLE = re.compile(r"^\s*(?:here\s+(?:is|are)\b[^\n]*?:|explanation\s*:|facts\s*:)\s*", re.I)

# Topic check. If Llama talks about one of these topics, the evidence must contain a signal (or
# entity) about it. Signal ids are the detector's rule ids (kavach/sms_rules.py, urlkit).
_TOPICS = {
    "credentials": (re.compile(r"\b(?:otp|pin|cvv|password|passcode|secret code)\b", re.I),
                    {"S_ASK_CREDENTIALS", "S_UPI_COLLECT", "L_OTP_NOTICE", "L_DELIVERY_OTP"}),
    "phone_call": (re.compile(r"\bcall(?:s|ed|ing)?\b|\bphone\s+number\b|\bnumber\s+(?:given|in\s+the\s+message)\b", re.I),
                   {"S_CALL_BACK", "S_AUTHORITY_ARREST"}),
    "payment": (re.compile(r"\b(?:pay|paid|payment|fee|deposit|charges?|rupees|rs\.?)\b|₹", re.I),
                {"S_JOB_TASK", "S_DELIVERY_PROBLEM", "S_INVESTMENT", "S_LOAN_OFFER", "S_UPI_COLLECT", "S_HEY_MUM",
                 "S_REFUND_TAX", "L_TXN_ALERT", "L_ORDER_STATUS"}),
    "app_install": (re.compile(r"\b(?:install|apk|anydesk|teamviewer|remote\s+(?:access|control))\b", re.I),
                    {"S_REMOTE_ACCESS"}),
}


def _unsupported_topics(text: str, ev: dict) -> list:
    ids = {s.get("id") for s in ev.get("signals", [])}
    has_phone = bool(ev.get("entities", {}).get("has_phone_number"))
    out = []
    for name, (pat, support) in _TOPICS.items():
        if pat.search(text) and not (ids & support) and not (name == "phone_call" and has_phone):
            out.append(name)
    return out


def _clean(llm_text: str) -> str:
    """Remove special tokens and prompt echoes, and drop a sentence cut off by the token cap."""
    text = _SPECIAL.sub("", llm_text or "").strip()
    text = _PREAMBLE.sub("", text).strip()
    if text and text[-1] not in ".!?":
        cut = max(text.rfind(". "), text.rfind("! "), text.rfind("? "))
        text = text[:cut + 1] if cut > 0 else text
    # A 1B model at temperature 0 can loop ("You should not ... . You should not ... ."). Keep each
    # sentence once, in order.
    seen, kept = set(), []
    for s in re.split(r"(?<=[.!?])\s+", text):
        key = re.sub(r"\W+", " ", s).strip().lower()
        if key and key not in seen:
            seen.add(key)
            kept.append(s.strip())
    return " ".join(kept)


def check_output(llm_text: str, ev: dict) -> dict:
    """All checks on Llama's text. Any failure -> use the template from the playbook instead."""
    text = _clean(llm_text)
    reasons = []
    if len(text) < 20:
        reasons.append("empty_or_too_short")
    g = advisor.check_grounding(text, ev)           # invented phone numbers / links
    if not g["ok"]:
        reasons.append("ungrounded")
    label = ev["verdict"]["label"]
    if label != "safe" and _SAYS_SAFE.search(text):
        reasons.append("contradicts_verdict")
    if label == "safe" and _SAYS_SCAM.search(text):
        reasons.append("contradicts_verdict")
    if label == "suspicious" and _LIKELY_SCAM.search(text):   # detector is unsure; "likely" overstates it
        reasons.append("overstates_suspicious")
    if _DIRECTS.search(text):
        reasons.append("directs_to_link_or_number")
    if _HARM_DONE.search(text):     # the detector only knows a message arrived, not that anyone lost anything
        reasons.append("claims_harm_happened")
    if _OVERCLAIM.search(text):
        reasons.append("overclaims_certainty")
    topics = _unsupported_topics(text, ev)          # claims about OTPs, calls, payments, apps with no evidence
    if topics:
        reasons.append("unsupported_topic:" + ",".join(topics))
    return {"ok": not reasons, "reasons": reasons, "grounding": g, "text": text}


def finalize(llm_text: str, evidence_json: str, language: str = "en") -> str:
    """Return what the screen shows: Llama's text if it passes every check, else the template."""
    ev = json.loads(evidence_json)
    chk = check_output(llm_text, ev)
    v = ev["verdict"]
    lang = language if language in ("en", "hi") else "en"
    actions = [advisor.REMEDIATION[a][lang] for a in ev["remediation"] if a in advisor.REMEDIATION][:3]
    if chk["ok"]:
        out = {"headline": advisor.BAND_TEXT[v["label"]][lang], "explanation": chk["text"], "actions": actions,
               "source": "llama"}
    else:
        out = dict(advisor.template_explanation(ev, language))
    out.update({"verdict": v, "check": {"ok": chk["ok"], "reasons": chk["reasons"]}})
    return _dumps(out)


# ----------------------------------------------------------------------------------- diagnostics
def selftest() -> str:
    """Environment report: Python/NumPy versions, model files, one sample verdict."""
    import numpy as np
    t0 = time.perf_counter()
    det = _detector()
    load_ms = (time.perf_counter() - t0) * 1000
    ev = det.analyze_message("Dear customer your SBI KYC is expired, account will be blocked today. "
                             "Update now: http://sbi-kyc-update.xyz/login", sender="+919812345678")
    return _dumps({
        "python": platform.python_version(), "machine": platform.machine(), "numpy": np.__version__,
        "model_dir": _model_dir(), "model_files_ok": True, "detector_load_ms": round(load_ms, 1),
        "sample_verdict": ev["verdict"], "sample_category": ev.get("category_text"),
    })


def cold_start(out_path: str, python_start_ms: float) -> str:
    """First use after a fresh process: import + load the detector + first verdict (same message as
    bench/run_bench.py's cold_start). Python start time is measured in Kotlin and passed in."""
    t = time.perf_counter()
    from kavach.pipeline import Detector
    d = Detector()                       # same as run_bench (network model included)
    t1 = time.perf_counter()
    d.analyze_message("Your SBI account is blocked. Update KYC at http://sbi-kyc.xyz now", None, with_prompt=False)
    t2 = time.perf_counter()
    row = {"ts": time.time(), "python_start_ms": round(python_start_ms, 1), "load_ms": round((t1 - t) * 1000, 1),
           "first_verdict_ms": round((t2 - t1) * 1000, 2)}
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    return _dumps(row)


def run_bench(root: str, args_json: str) -> str:
    """Run kavach-edge/bench/run_bench.py UNCHANGED inside the app process (protocol rule: same code on
    every device). `root` holds a pushed copy of bench/, data/, models/ and demo/pcaps/; the script
    writes results/bench/bench_<label>.json there. stdout goes to a log file (logcat hides it here)."""
    import contextlib
    import runpy
    import sys
    args = json.loads(args_json)
    os.makedirs(os.path.join(root, "results", "bench"), exist_ok=True)
    log = os.path.join(root, "results", "bench", "stdout.txt")
    old_argv = sys.argv
    sys.argv = [os.path.join(root, "bench", "run_bench.py")] + args
    try:
        with open(log, "a", encoding="utf-8") as f, contextlib.redirect_stdout(f):
            runpy.run_path(sys.argv[0], run_name="__main__")
    except SystemExit:
        pass
    finally:
        sys.argv = old_argv
    return _dumps({"done": True, "log": log})


def score_file(in_path: str, out_path: str) -> str:
    """Parity check: score every line of a JSONL file ({"text","sender"} or {"url"}) and write
    one result line each. The same function runs on the laptop, so outputs can be diffed."""
    det = _detector()
    n = 0
    with open(in_path, encoding="utf-8") as f, open(out_path, "w", encoding="utf-8") as g:
        for line in f:
            r = json.loads(line)
            ev = det.analyze_url(r["url"], with_prompt=False) if "url" in r else \
                det.analyze_message(r["text"], sender=r.get("sender"), with_prompt=False)
            g.write(_dumps({"i": n, "label": ev["verdict"]["label"], "risk": ev["verdict"]["risk_score"],
                            "category": ev.get("category"), "model_outputs": ev.get("model_outputs")}) + "\n")
            n += 1
    return _dumps({"scored": n, "out": out_path})
