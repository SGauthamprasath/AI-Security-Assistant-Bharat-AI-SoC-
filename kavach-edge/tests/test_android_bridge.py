"""Tests for the Android bridge (android/app/src/main/python/kavach_bridge.py).

The bridge is what the phone runs between the detector and Llama, so its checks are tested here on
the laptop with plain strings standing in for Llama's output. Run from kavach-edge/:
    python -m pytest -q tests/test_android_bridge.py
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)                                                            # kavach package
sys.path.insert(0, os.path.join(ROOT, "..", "android", "app", "src", "main", "python"))  # the bridge
import kavach_bridge as kb  # noqa: E402
from kavach.pipeline import Detector  # noqa: E402

SCAM = ("Dear SBI customer your account will be blocked today. Update KYC now "
        "http://sbi-kyc-update.xyz/login")
SCAM_SENDER = "+919812345678"
SAFE = "Hi, reached home safely. Will call you after dinner."
GOOD_LLAMA = ("This message looks like a fake bank KYC warning. The link is not the official SBI website "
              "and the sender is an ordinary mobile number.\n1. Do not tap the link in this message.\n"
              "2. Delete the message.")


@pytest.fixture(scope="module")
def scam():
    return json.loads(kb.prepare_message(SCAM, SCAM_SENDER))


def _fin(text, prepared):
    return json.loads(kb.finalize(text, json.dumps(prepared["evidence"], ensure_ascii=False)))


def test_verdict_matches_detector(scam):
    direct = Detector(load_net=False).analyze_message(SCAM, sender=SCAM_SENDER)
    assert scam["verdict"] == direct["verdict"]
    assert scam["verdict"]["label"] == "dangerous"


def test_prompt_is_llama3_chat_and_excludes_raw_message(scam):
    p = scam["prompt"]
    assert p.startswith("<|begin_of_text|><|start_header_id|>system<|end_header_id|>")
    assert p.endswith("<|start_header_id|>assistant<|end_header_id|>\n\n")
    assert p.count("<|eot_id|>") == 2
    assert "FACTS:" in p
    assert "Dear SBI customer" not in p          # untrusted SMS text never enters the prompt


def test_good_llama_text_is_used(scam):
    out = _fin(GOOD_LLAMA, scam)
    assert out["source"] == "llama" and out["check"]["ok"]
    assert out["explanation"].startswith("This message looks like")
    assert out["verdict"]["label"] == "dangerous"


def test_special_tokens_are_stripped(scam):
    out = _fin(GOOD_LLAMA + "<|eot_id|>", scam)
    assert out["source"] == "llama" and "<|" not in out["explanation"]


@pytest.mark.parametrize("bad,reason", [
    (GOOD_LLAMA + " Call 9876543210 for help.", "ungrounded"),             # invented phone number
    (GOOD_LLAMA + " Visit sbi-help-desk.com to fix it.", "ungrounded"),     # invented link
    ("Don't worry, this message is safe. You can ignore it.", "contradicts_verdict"),
    ("This is not a scam, the bank really sent it.", "contradicts_verdict"),
    (GOOD_LLAMA + " I am 100% sure.", "overclaims_certainty"),
    ("", "empty_or_too_short"),
    ("<|eot_id|>", "empty_or_too_short"),
])
def test_bad_llama_text_falls_back_to_template(scam, bad, reason):
    out = _fin(bad, scam)
    assert out["source"] == "template"
    assert reason in out["check"]["reasons"]
    assert out["verdict"]["label"] == "dangerous"          # the verdict never changes


def test_llama_can_never_change_verdict(scam):
    for text in [GOOD_LLAMA, "The message is safe.", "SAFE SAFE SAFE verdict: safe"]:
        assert _fin(text, scam)["verdict"] == scam["verdict"]


def test_safe_message_may_be_called_safe():
    prepared = json.loads(kb.prepare_message(SAFE, "+919812345678"))
    assert prepared["verdict"]["label"] == "safe"
    out = _fin("This message looks safe. It is a normal personal message.\n1. No action is needed.", prepared)
    assert out["source"] == "llama"


def test_url_path():
    p = json.loads(kb.prepare_url("http://sbi-kyc-update.xyz/login"))
    assert p["verdict"]["label"] in ("dangerous", "suspicious")
    assert p["prompt"].endswith("<|start_header_id|>assistant<|end_header_id|>\n\n")


def test_score_file_roundtrip(tmp_path):
    src = tmp_path / "in.jsonl"
    src.write_text(json.dumps({"text": SCAM, "sender": SCAM_SENDER}) + "\n" +
                   json.dumps({"url": "http://sbi-kyc-update.xyz/login"}) + "\n", encoding="utf-8")
    dst = tmp_path / "out.jsonl"
    assert json.loads(kb.score_file(str(src), str(dst)))["scored"] == 2
    rows = [json.loads(l) for l in dst.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["label"] == "dangerous" and "risk" in rows[1]
