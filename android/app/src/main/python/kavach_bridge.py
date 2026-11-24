"""Thin bridge between the Android app (Kotlin) and the unchanged detector in kavach/.

Kotlin calls these functions through Chaquopy and gets plain JSON strings back, so no Python
objects cross the language boundary. Nothing here changes a verdict: it only calls the detector.
"""
from __future__ import annotations

import json
import os
import platform
import time

_DETECTOR = None

# Every file the detector reads. urlkit silently skips missing list files (os.path.exists), which
# would quietly change results, so we check they are really on disk before trusting any output.
_REQUIRED = ["fusion.json", "psl_multi.json", "shared_hosting.txt", "sms_lr.bin", "sms_lr.json",
             "tld_rate.json", "trusted_domains.txt", "url_hgb.json", "url_hgb.npz", "url_ngram.bin"]


def _model_dir() -> str:
    from kavach import urlkit
    return urlkit.MODEL_DIR


def _detector():
    """Load the detector once (about a few ms) and reuse it."""
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


def selftest() -> str:
    """Environment report for the Step 1 smoke test."""
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


def analyze_message(text: str, sender: str | None = None) -> str:
    """Full evidence JSON for an SMS (includes the advisor prompt)."""
    return _dumps(_detector().analyze_message(text, sender=sender or None))


def analyze_url(url: str) -> str:
    return _dumps(_detector().analyze_url(url))
