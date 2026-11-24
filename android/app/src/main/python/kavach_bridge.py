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

MAX_NEW_TOKENS = 160          # Kotlin stops generation after this many tokens (about 13 s at ~12 tok/s)


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
    The SMS text itself is never in the prompt: advisor.build_prompt only passes detector facts.
    """
    return ("<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + system + "<|eot_id|>"
            "<|start_header_id|>user<|end_header_id|>\n\n" + user + "<|eot_id|>"
            "<|start_header_id|>assistant<|end_header_id|>\n\n")


def _package(ev: dict, language: str) -> str:
    """Everything the UI needs before Llama runs."""
    p = ev.get("advisor_prompt") or advisor.build_prompt(ev, language)
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
_SAYS_SAFE = re.compile(r"\b(?:is|looks|seems|appears)\s+(?:to\s+be\s+)?(?:safe|genuine|legitimate|real|harmless)\b"
                        r"|\bnot\s+(?:a\s+)?(?:scam|fraud)\b|\bnothing\s+to\s+worry\b", re.I)
_OVERCLAIM = re.compile(r"\b100\s*%|\b(?:always\s+(?:right|correct)|definitely|guaranteed)\b", re.I)


def check_output(llm_text: str, ev: dict) -> dict:
    """All checks on Llama's text. Any failure -> use the template from the playbook instead."""
    text = _SPECIAL.sub("", llm_text or "").strip()
    reasons = []
    if len(text) < 20:
        reasons.append("empty_or_too_short")
    g = advisor.check_grounding(text, ev)           # invented phone numbers / links
    if not g["ok"]:
        reasons.append("ungrounded")
    if ev["verdict"]["label"] != "safe" and _SAYS_SAFE.search(text):
        reasons.append("contradicts_verdict")
    if _OVERCLAIM.search(text):
        reasons.append("overclaims_certainty")
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
