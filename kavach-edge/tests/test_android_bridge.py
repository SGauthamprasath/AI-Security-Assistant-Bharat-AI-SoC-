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


# Sentences Llama really wrote on the V40e (24 Nov) for the SBI YONO message, with the old wide prompt.
# None of these topics is in that message's evidence, so each must send the screen to the template.
REAL_PHONE_OUTPUT = [
    ("The message asks you to share your account information (like your PIN, CVV, or password) with "
     "someone who claims to be a bank or company.", "unsupported_topic:credentials"),
    ("The message also asks you to call the number given in the message, which is not the official number "
     "of the bank or company.", "unsupported_topic:phone_call"),
    ("The message you received is a scam. It says you need to take action to protect your account.",
     "overclaims_certainty"),
]


@pytest.mark.parametrize("bad,reason", REAL_PHONE_OUTPUT)
def test_real_phone_hallucinations_are_caught(scam, bad, reason):
    out = _fin(bad, scam)
    assert out["source"] == "template" and reason in out["check"]["reasons"]


def test_safe_verdict_called_scam_is_caught():
    # Real phone output (24 Nov) for a SAFE personal message, caused by a prompt bug since fixed.
    prepared = json.loads(kb.prepare_message(SAFE, "+919812345678"))
    out = _fin("The message is likely a scam because it uses a generic and unoriginal tone, which is often "
               "used by scammers to trick people into revealing sensitive information.", prepared)
    assert out["source"] == "template" and "contradicts_verdict" in out["check"]["reasons"]
    ok = _fin("No warning signs were found. The wording looks like an ordinary personal message, "
              "not a scam.", prepared)
    assert ok["source"] == "llama", ok["check"]


@pytest.mark.parametrize("label,phrase", [("dangerous", "very likely a scam"), ("suspicious", "never 'likely'"),
                                          ("safe", "Do not call it a scam")])
def test_explain_prompt_stance_follows_verdict(label, phrase):
    from kavach import advisor
    ev = {"verdict": {"label": label, "risk_score": 0.5, "confidence": "medium"}, "signals": [],
          "entities": {"urls": []}, "category_text": "x"}
    assert phrase in advisor.build_explain_prompt(ev)["system"]


def test_topic_allowed_when_evidence_supports_it():
    p = json.loads(kb.prepare_message("Your account is on hold. Share the OTP you received to unblock it "
                                      "immediately or call 9876543210.", "+919812345678"))
    ids = {s["id"] for s in p["evidence"]["signals"]}
    assert "S_ASK_CREDENTIALS" in ids
    out = _fin("This message is likely a scam because it asks for your OTP, which banks never ask for.", p)
    assert "unsupported_topic:credentials" not in out["check"]["reasons"]


def test_preamble_and_cut_sentence_are_cleaned(scam):
    out = _fin("Here are the FACTS explained in simple English:\n" + GOOD_LLAMA.split("\n")[0] +
               " The sender also", scam)
    assert out["source"] == "llama"
    assert out["explanation"].startswith("This message looks like") and out["explanation"].endswith(".")


def test_explain_prompt_has_no_actions(scam):
    p = scam["prompt"]
    assert "allowed_actions" not in p and "Do not tap the link" not in p
    assert "2 or 3 short sentences" in p
    assert scam["max_new_tokens"] <= 100


def test_actions_always_from_playbook(scam):
    from kavach import advisor
    out = _fin(GOOD_LLAMA, scam)
    playbook = {advisor.REMEDIATION[a]["en"] for a in scam["evidence"]["remediation"]}
    assert out["actions"] and all(a in playbook for a in out["actions"])


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
