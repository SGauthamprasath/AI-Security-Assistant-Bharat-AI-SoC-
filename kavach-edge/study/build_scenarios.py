#!/usr/bin/env python3
"""Build the user-study scenarios from REAL pipeline output and bake them into one self-contained offline HTML app.

    python3 study/build_scenarios.py      -> study/scenarios.json, study/study_app.html

Design (within-subject, counterbalanced):
  * 10 scenarios drawn from the DEV hand-written benchmark, stratified by category with a fixed seed (6 scams, 4 genuine) - NOT filtered by whether
    the detector got them right; `system_correct` is stored so the report can state it.
  * Each participant sees every scenario once. For half of them the system output is shown as RAW EVIDENCE (what a detector without an explanation
    layer exposes: verdict, risk score, rule ids, contributions); for the other half as PLAIN-LANGUAGE EXPLANATION (headline, why, what to do - the
    `advisor.template_explanation`, which is the same shape the on-device LLM must produce). Condition per scenario alternates by participant number.
  * Per trial: action choice, reason choice (comprehension), confidence, trust, time.
"""
import hashlib
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import advisor  # noqa: E402
from kavach.pipeline import Detector  # noqa: E402

ACTIONS = ["Ignore it: delete it and do not click, reply or call", "Open the link to check whether it is real", "Reply with the details they ask for",
           "Call the phone number given in the message", "It looks genuine: no special action needed"]
CORRECT_SCAM, CORRECT_LEGIT = 0, 4
REASONS = {"bank_kyc": "a fake bank / KYC warning", "reward": "a fake reward or prize", "job": "a fake job / task offer", "delivery": "a fake delivery problem",
           "utility": "a fake electricity / utility cut-off threat", "authority": "a fake police / customs / court threat", "remote_access": "a trick to make you install a remote-control app",
           "investment": "a fake investment / trading scheme", "loan": "a fake instant-loan offer", "upi_scam": "a fake UPI payment request", "family": "someone pretending to be a relative in trouble",
           "refund": "a fake refund / tax message", "credential_theft": "a trick to steal your password, PIN or OTP", "advance_fee": "a trick to make you pay a fee first",
           "romance": "a romance / friendship scam", "legit": "an ordinary genuine message (OTP, bill, order or appointment)"}


def reason_for(cat_key, truth):
    return REASONS["legit"] if truth == 0 else REASONS.get(cat_key, "a scam message")


def main():
    det = Detector()
    rows = [json.loads(l) for l in open(os.path.join(ROOT, "data", "kavachbench_in.jsonl"))]
    rng = random.Random(7)
    by = {}
    for r in rows:
        by.setdefault((r["label"], r["category"]), []).append(r)
    scam_cats = sorted(k for k in by if k[0] == 1)
    legit_cats = sorted(k for k in by if k[0] == 0)
    rng.shuffle(scam_cats)
    rng.shuffle(legit_cats)
    pick = [rng.choice(by[k]) for k in scam_cats[:6]] + [rng.choice(by[k]) for k in legit_cats[:4]]
    rng.shuffle(pick)
    sc = []
    for i, r in enumerate(pick, 1):
        ev = det.analyze_message(r["text"], r["sender"], with_prompt=False)
        expl = advisor.template_explanation(ev, "en")
        truth = r["label"]
        verdict = ev["verdict"]["label"]
        flagged = verdict != "safe"
        raw = {"verdict": verdict.upper(), "risk_score": ev["verdict"]["risk_score"], "category_id": ev["category"],
               "signals": [{"id": s["id"], "direction": s["direction"], "contribution": s["contribution"]} for s in ev["signals"][:7]]}
        correct_reason = reason_for(r["category"], truth)
        # the explanation the participant would see names the category the SYSTEM inferred; the quiz asks about the true message type
        distract = [v for k, v in REASONS.items() if v != correct_reason]
        rng.shuffle(distract)
        opts = [correct_reason] + distract[:3]
        rng.shuffle(opts)
        sc.append({"id": f"S{i:02d}", "sender": r["sender"] or "Unknown contact (chat message)", "text": r["text"], "truth": truth, "category": r["category"], "system_verdict": verdict, "system_correct": bool(flagged == bool(truth)),
                   "raw": raw, "explanation": {"headline": expl["headline"], "explanation": expl["explanation"], "actions": expl["actions"]},
                   "q_action": {"options": ACTIONS, "correct": CORRECT_SCAM if truth else CORRECT_LEGIT},
                   "q_reason": {"options": opts, "correct": opts.index(correct_reason)}})
    json.dump(sc, open(os.path.join(ROOT, "study", "scenarios.json"), "w"), indent=1, ensure_ascii=False)
    tpl = open(os.path.join(ROOT, "study", "study_app.template.html"), encoding="utf-8").read()
    html = tpl.replace("/*__SCENARIOS__*/[]", json.dumps(sc, ensure_ascii=False))
    open(os.path.join(ROOT, "study", "study_app.html"), "w", encoding="utf-8").write(html)
    print(f"{len(sc)} scenarios ({sum(s['truth'] for s in sc)} scam / {sum(1 - s['truth'] for s in sc)} genuine); detector correct on {sum(s['system_correct'] for s in sc)}/{len(sc)}")
    print("wrote study/scenarios.json and study/study_app.html (self-contained, works offline in any browser)")


if __name__ == "__main__":
    main()
