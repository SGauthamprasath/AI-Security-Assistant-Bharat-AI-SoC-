import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
jsonschema = pytest.importorskip("jsonschema")
from kavach.pipeline import Detector  # noqa: E402


def test_all_evidence_kinds_validate_against_schema():
    schema = json.load(open(os.path.join(ROOT, "schemas", "evidence.schema.json")))
    det = Detector()
    evs = [det.analyze_message("Pay Rs 1 to verify KYC http://x-kyc.top", "VK-X", with_prompt=False),
           det.analyze_message("Dinner at 8?", None, with_prompt=False),
           det.analyze_url("https://paytm-login.top/a", with_prompt=False)]
    evs += det.analyze_pcap(os.path.join(ROOT, "demo", "pcaps", "port_scan.pcap"), with_prompt=False)["alerts"]
    for ev in evs:
        jsonschema.validate(ev, schema)


def test_static_audit_finds_no_network_imports():
    sys.path.insert(0, os.path.join(ROOT, "offline_proof"))
    import verify_offline
    assert verify_offline.static_audit()["pass"]


def test_runtime_offline_proof_passes():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "offline_proof", "verify_offline.py")], capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0, p.stdout[-800:]
