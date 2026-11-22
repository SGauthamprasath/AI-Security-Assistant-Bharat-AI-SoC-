"""Core behaviour tests: run with `python3 -m pytest -q tests`."""
import json
import os
import sys

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import advisor, fusion, netflow, pcapread  # noqa: E402
from kavach.pipeline import Detector  # noqa: E402
from kavach.treeexport import TreeRuntime  # noqa: E402


@pytest.fixture(scope="module")
def det():
    return Detector()


def test_scam_is_dangerous(det):
    ev = det.analyze_message("Dear SBI customer your account will be blocked today. Update KYC now http://sbi-kyc-update.xyz/login", "VK-SBIYNO", with_prompt=False)
    assert ev["verdict"]["label"] == "dangerous"
    assert "REPORT_1930" in ev["remediation"]


def test_genuine_otp_is_safe(det):
    ev = det.analyze_message("123456 is your OTP for login to your Bank account. Do not share it with anyone.", "AX-HDFCBK", with_prompt=False)
    assert ev["verdict"]["label"] == "safe"


def test_typosquat_flagged_official_trusted(det):
    assert det.analyze_url("https://amaz0n-in-support.top/gp/help", with_prompt=False)["verdict"]["label"] != "safe"
    assert det.analyze_url("https://www.amazon.in/gp/help/customer/display.html", with_prompt=False)["verdict"]["label"] == "safe"


def test_evidence_never_carries_the_full_message(det):
    text = "Your parcel is held at depot. Pay Rs 49 redelivery fee at http://indiapost-redeliver.top/p"
    ev = det.analyze_message(text, None, with_prompt=True)
    blob = json.dumps(ev).lower()
    assert "redelivery fee" not in blob and "pay rs 49" not in blob           # the sentence is never copied across
    for s_ in ev["signals"]:
        assert s_.get("match") is None or len(str(s_["match"])) <= max(40, len(str(s_.get("match")))) and (s_["source"] != "rule" or s_["modality"] != "sms" or len(s_["match"]) <= 40)
    assert ev["privacy"]["raw_text_included"] is False and ev["privacy"]["network_calls"] == 0 and ev["privacy"]["max_snippet_chars"] == 40


def test_tree_runtime_matches_reference_loop():
    for f in ("url_hgb.npz", "net_hgb.npz"):
        t = TreeRuntime(os.path.join(ROOT, "models", f))
        rng = np.random.default_rng(1)
        X = rng.normal(size=(200, len(t.feature_names))) * rng.choice([1, 50, 5000], size=len(t.feature_names))
        X[rng.random(X.shape) < 0.05] = np.nan
        K = 1 if t.n_classes == 2 else t.n_classes
        ref = np.tile(t.baseline.reshape(K, 1), (1, len(X))).astype(float)
        rows = np.arange(len(X))
        for r, c in zip(t.roots, t.tree_class):
            idx = np.full(len(X), r, dtype=np.int64)
            while True:
                leaf = t.is_leaf[idx].astype(bool)
                if leaf.all():
                    break
                f_ = np.where(leaf, 0, t.feature[idx]); xv = X[rows, f_]
                gl = np.where(np.isnan(xv), t.miss_left[idx].astype(bool), xv <= t.threshold[idx])
                idx = np.where(leaf, idx, np.where(gl, t.left[idx], t.right[idx]))
            ref[c] += t.value[idx]
        assert np.abs(t.raw(X) - ref).max() < 1e-9


@pytest.mark.parametrize("name,expect", [("normal_browsing", None), ("port_scan", "port scan"), ("syn_flood", "syn flood"), ("ping_flood", "ping flood"), ("smurf_like", "smurf")])
def test_pcap_alerts(det, name, expect):
    r = det.analyze_pcap(os.path.join(ROOT, "demo", "pcaps", name + ".pcap"), with_prompt=False)
    labels = " ".join(a["category_text"].lower() for a in r["alerts"])
    if expect is None:
        assert r["summary"]["flagged"] == 0
    else:
        assert expect in labels


def test_pcap_reader_handles_pcapng_roundtrip(tmp_path):
    # build a minimal pcapng by hand: SHB + IDB(ethernet) + one EPB carrying an Ethernet/IPv4/TCP SYN
    import struct
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = bytes([0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])
    tcp = struct.pack("!HHIIBBHHH", 1234, 80, 0, 0, 5 << 4, 0x02, 1024, 0, 0)
    frame = eth + ip + tcp
    pad = (-len(frame)) % 4
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    idb = struct.pack("<IIHHI", 1, 20, 1, 0, 0) + struct.pack("<I", 20)
    epb_len = 32 + len(frame) + pad
    epb = struct.pack("<IIIIIII", 6, epb_len, 0, 0, 1_000_000, len(frame), len(frame)) + frame + b"\x00" * pad + struct.pack("<I", epb_len)
    p = tmp_path / "t.pcapng"
    p.write_bytes(shb + idb + epb)
    pk = list(pcapread.read_packets(str(p)))
    assert len(pk) == 1 and pk[0].proto == "tcp" and pk[0].dport == 80 and pk[0].src == "10.0.0.1" and pk[0].flags == 2


def test_grounding_checker_rejects_invented_number(det):
    ev = det.analyze_message("Update KYC http://sbi-kyc.xyz", None, with_prompt=False)
    assert advisor.check_grounding("Call 9876543210 now", ev)["ok"] is False
    assert advisor.check_grounding("Do not tap the link.", ev)["ok"] is True


def test_fusion_weights_respect_sign_bounds():
    fz = fusion.Fusion()
    for name, w in zip(fusion.MSG_FEATURES, fz.msg_w):
        if name.startswith("S_") or name in ("z_sms", "z_url"):
            assert w >= 0
        if name.startswith("L_"):
            assert w <= 0
