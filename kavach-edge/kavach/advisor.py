"""Grounded-advisor interface.

The challenge requires a Llama-family model (via ExecuTorch) for the *advisory / reasoning* step.  This
module defines the contract between the deterministic detector and that LLM:

  * ``REMEDIATION`` - a closed catalogue of safe actions (English + Hindi).  The LLM may only recommend
    actions whose ids appear in ``evidence["remediation"]`` -> no invented advice, no hallucinated helplines.
  * ``build_prompt(evidence)`` - a compact prompt (<= ~350 tokens) that carries ONLY facts from the evidence.
  * ``template_explanation(evidence)`` - a deterministic fallback with the same output shape, used (a) when
    the LLM is not loaded, (b) as the baseline condition in the user study and (c) as a faithfulness
    reference.  It is NOT a substitute for the Llama advisor.
  * ``check_grounding(text, evidence)`` - cheap guard that flags LLM output mentioning phone numbers / URLs /
    actions that are not in the evidence.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List

REMEDIATION: Dict[str, Dict[str, str]] = {
    "DONT_OPEN_LINK": {"en": "Do not tap the link in this message.", "hi": "इस संदेश में दिए गए लिंक पर क्लिक न करें।"},
    "DELETE_MESSAGE": {"en": "Delete the message.", "hi": "इस संदेश को डिलीट कर दें।"},
    "BLOCK_SENDER": {"en": "Block the sender.", "hi": "भेजने वाले को ब्लॉक करें।"},
    "NEVER_SHARE_CREDENTIALS": {"en": "Never share your OTP, PIN, CVV or password with anyone. Real banks never ask for them.", "hi": "अपना OTP, PIN, CVV या पासवर्ड किसी को न बताएं। असली बैंक कभी नहीं माँगते।"},
    "VERIFY_OFFICIAL_CHANNEL": {"en": "If you are worried, check using the official app or the phone number printed on your card or passbook, not the one in the message.", "hi": "चिंता हो तो आधिकारिक ऐप या कार्ड/पासबुक पर छपे नंबर से जाँचें, संदेश में दिए नंबर से नहीं।"},
    "DONT_CALL_BACK": {"en": "Do not call back the number given in the message.", "hi": "संदेश में दिए गए नंबर पर वापस कॉल न करें।"},
    "DONT_INSTALL_APK": {"en": "Do not install any app or give remote access (AnyDesk, TeamViewer) because of this message.", "hi": "इस संदेश के कहने पर कोई ऐप इंस्टॉल न करें और न ही रिमोट एक्सेस दें।"},
    "DONT_PAY_ADVANCE": {"en": "Do not pay any fee, deposit or 'processing charge' to receive money, a job or a prize.", "hi": "पैसे, नौकरी या इनाम पाने के लिए कोई फीस या अग्रिम राशि न दें।"},
    "REPORT_1930": {"en": "If you already lost money or shared details, call 1930 (National Cyber Crime Helpline) at once and report at cybercrime.gov.in.", "hi": "अगर पैसे गँवा चुके हैं या जानकारी दे दी है तो तुरंत 1930 (साइबर क्राइम हेल्पलाइन) पर कॉल करें और cybercrime.gov.in पर शिकायत करें।"},
    "REPORT_CHAKSHU": {"en": "You can report the message on the Chakshu facility of Sanchar Saathi (sancharsaathi.gov.in).", "hi": "आप इस संदेश की शिकायत संचार साथी (sancharsaathi.gov.in) के चक्षु पर कर सकते हैं।"},
    "IF_ALREADY_CLICKED": {"en": "If you already clicked or entered details: call your bank to block the card/UPI, change your passwords, and call 1930.", "hi": "अगर आप क्लिक कर चुके हैं या जानकारी भर दी है: बैंक को कॉल करके कार्ड/UPI ब्लॉक कराएं, पासवर्ड बदलें और 1930 पर कॉल करें।"},
    "NEVER_SHARE_CREDENTIALS_UPI": {"en": "You only enter a UPI PIN to PAY money, never to receive it.", "hi": "UPI PIN केवल पैसे भेजने के लिए डालते हैं, पाने के लिए कभी नहीं।"},
    "NO_ACTION_NEEDED": {"en": "No action is needed. Keep the usual care: never share OTPs or PINs.", "hi": "किसी कार्रवाई की ज़रूरत नहीं है। OTP या PIN किसी से साझा न करें।"},
    "ISOLATE_DEVICE": {"en": "Disconnect the affected device from Wi-Fi/the network until it is checked.", "hi": "जाँच होने तक प्रभावित डिवाइस को Wi-Fi/नेटवर्क से हटा दें।"},
    "RESTART_ROUTER": {"en": "Restart your router; if the problem returns, contact your internet provider.", "hi": "अपना राउटर रीस्टार्ट करें; समस्या बनी रहे तो इंटरनेट प्रदाता से संपर्क करें।"},
    "CHANGE_ROUTER_PASSWORD": {"en": "Change your router's admin and Wi-Fi passwords and turn off remote management.", "hi": "राउटर का एडमिन और Wi-Fi पासवर्ड बदलें और रिमोट मैनेजमेंट बंद करें।"},
    "CHANGE_PASSWORDS": {"en": "Change the passwords of the affected accounts and devices.", "hi": "प्रभावित खातों और डिवाइस के पासवर्ड बदलें।"},
    "CHECK_ROUTER_LOGS": {"en": "Check the router's connected-devices list and remove any device you do not recognise.", "hi": "राउटर में जुड़े डिवाइस की सूची देखें और अनजान डिवाइस हटा दें।"},
    "RUN_MALWARE_SCAN": {"en": "Run a malware scan on the affected device.", "hi": "प्रभावित डिवाइस पर मैलवेयर स्कैन चलाएं।"},
}
BAND_TEXT = {
    "dangerous": {"en": "DANGEROUS - very likely a scam / attack", "hi": "खतरनाक - लगभग निश्चित रूप से धोखाधड़ी/हमला"},
    "suspicious": {"en": "SUSPICIOUS - be careful", "hi": "संदिग्ध - सावधान रहें"},
    "safe": {"en": "LOOKS SAFE", "hi": "सुरक्षित लगता है"},
}
CATEGORY_TEXT = {
    "bank_kyc": "a fake bank / KYC warning", "credential_theft": "an attempt to steal your OTP, PIN or password", "reward_lottery": "a fake prize or reward",
    "job_task_scam": "a fake job / online-task offer", "delivery_scam": "a fake parcel or delivery problem", "utility_scam": "a fake electricity / gas disconnection threat",
    "authority_impersonation": "someone pretending to be police or a government agency", "remote_access_scam": "an attempt to make you install a remote-control app",
    "investment_scam": "a fake investment offer", "loan_scam": "a fake loan offer", "upi_scam": "a UPI 'collect / receive money' trick", "family_impersonation": "someone pretending to be a family member",
    "refund_scam": "a fake refund", "account_threat": "a fake account-blocking threat", "link_lure": "a suspicious link", "sender_mismatch": "a message that pretends to come from a bank",
    "phishing_url": "a fake website link", "dos": "a flood of connection attempts", "probe": "port scanning", "r2l": "an unauthorised remote-access attempt", "u2r": "privilege-escalation behaviour",
    "generic": "a suspicious message", "pressure": "a pressure tactic",
}


def top_reasons(evidence: Dict, k: int = 4) -> List[str]:
    sigs = [s for s in evidence["signals"] if s.get("direction") == ("risk" if evidence["verdict"]["label"] != "safe" else "reassuring")]
    sigs = sorted(sigs, key=lambda s: -abs(s["contribution"]))
    return [s["description"] for s in sigs[:k]]


def build_prompt(evidence: Dict, language: str = "en") -> Dict[str, str]:
    """Compact grounded prompt for the on-device Llama advisor."""
    v = evidence["verdict"]
    actions = [REMEDIATION[a]["en"] for a in evidence["remediation"] if a in REMEDIATION]
    facts = {
        "kind": evidence["input"]["type"], "verdict": v["label"], "risk_percent": round(100 * v["risk_score"]), "confidence": v["confidence"],
        "scam_type": evidence.get("category_text"), "reasons": top_reasons(evidence), "suspicious_domains": [u["registered_domain"] for u in evidence["entities"].get("urls", []) if u.get("flags")][:3],
        "allowed_actions": actions[:5],
    }
    if evidence["input"]["type"] == "flow_window":
        facts["network"] = {k: evidence["entities"][k] for k in ("src_ips", "dst_ip", "n_connections", "distinct_ports", "duration_s") if k in evidence["entities"]}
    lang = {"en": "simple English", "hi": "simple Hindi (Devanagari)", "ta": "simple Tamil"}.get(language, "simple English")
    system = ("You are Kavach, a calm on-device digital-safety assistant for non-technical people in India. "
              "Explain the detector's FACTS in " + lang + ", in at most 5 short sentences, then list the allowed actions as 1-3 numbered steps. "
              "Use ONLY the facts and allowed actions given. Never invent phone numbers, links, names or amounts. "
              "If verdict is 'safe', say so briefly. Do not use technical jargon.")
    user = "FACTS:\n" + json.dumps(facts, ensure_ascii=False)
    return {"system": system, "user": user, "facts": facts}


def build_explain_prompt(evidence: Dict, language: str = "en") -> Dict[str, object]:
    """Narrower prompt used by the Android app (added 24 Nov; build_prompt above is unchanged).

    Llama writes ONLY a 2-3 sentence explanation of the detector's reasons. The action steps are not
    in the prompt at all: the app shows them word for word from REMEDIATION. On the phone, the wider
    build_prompt made Llama turn playbook actions ("Do not call back the number...") into claims about
    the message ("it asks you to call a number") that the evidence did not support.
    """
    v = evidence["verdict"]
    facts = {
        "verdict": v["label"], "risk_percent": round(100 * v["risk_score"]), "confidence": v["confidence"],
        "scam_type": evidence.get("category_text") if v["label"] != "safe" else None,
        "reasons": top_reasons(evidence),
        "suspicious_domains": [u["registered_domain"] for u in evidence["entities"].get("urls", []) if u.get("flags")][:3],
    }
    lang = {"en": "simple English", "hi": "simple Hindi (Devanagari)", "ta": "simple Tamil"}.get(language, "simple English")
    # The stance must follow the verdict. A single "say it is likely a scam" line made Llama call a
    # SAFE message a scam on the phone (24 Nov).
    stance = {
        "dangerous": "The message is very likely a scam. Say 'likely', never that it is certain.",
        "suspicious": "The message MAY be a scam; the detector is not sure. Say 'may be', never 'likely'.",
        "safe": "The message looks safe. Say that no warning signs were found. Do not call it a scam.",
    }[v["label"]]
    system = ("You are Kavach, a calm phone safety assistant for non-technical people in India. "
              "In " + lang + ", write 2 or 3 short sentences that explain the verdict using ONLY the listed reasons. "
              + stance + " "
              "Do not give advice or steps: the app shows them separately. Do not add a heading or a list. "
              "Do not introduce yourself. "
              "Do not mention OTPs, PINs, passwords, phone calls, payments or apps unless a reason mentions them. "
              "Never invent phone numbers, links, names or amounts.")
    user = "FACTS:\n" + json.dumps(facts, ensure_ascii=False)
    return {"system": system, "user": user, "facts": facts}


def template_explanation(evidence: Dict, language: str = "en") -> Dict[str, object]:
    """Deterministic explanation with the same shape the LLM must produce."""
    v = evidence["verdict"]
    band = v["label"]
    cat = evidence.get("category_text") or CATEGORY_TEXT["generic"]
    reasons = top_reasons(evidence, 3)
    actions = [REMEDIATION[a][language if language in ("en", "hi") else "en"] for a in evidence["remediation"] if a in REMEDIATION][:3]
    head = BAND_TEXT[band][language if language in ("en", "hi") else "en"]
    if language == "hi":
        body = (f"यह {cat} जैसा लगता है।" if band != "safe" else "इसमें कोई स्पष्ट खतरा नहीं दिखा।") + (" कारण: " + " ".join(reasons) if reasons and band != "safe" else "")
    else:
        body = (f"This looks like {cat}." if band != "safe" else "Nothing in this looks dangerous.") + (" Why: " + " ".join(reasons) if reasons and band != "safe" else "")
    return {"headline": head, "explanation": body, "actions": actions, "source": "template"}


_PHONE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)|\b1800[\s-]?\d{3,}\b|\b1930\b")
_URL = re.compile(r"(?:https?://|www\.)\S+|\b[a-z0-9-]+\.(?:com|in|org|gov\.in|co\.in|net|xyz|top)\b", re.I)


def check_grounding(llm_text: str, evidence: Dict) -> Dict[str, object]:
    """Flag content in LLM output that is not backed by the evidence (cheap hallucination guard)."""
    allowed_text = json.dumps(evidence, ensure_ascii=False) + " " + " ".join(REMEDIATION[a]["en"] + REMEDIATION[a]["hi"] for a in REMEDIATION)
    bad_phones = [m for m in _PHONE.findall(llm_text) if re.sub(r"\D", "", m) not in re.sub(r"\D", "", allowed_text)]
    bad_urls = [m for m in _URL.findall(llm_text) if m.lower() not in allowed_text.lower()]
    return {"ok": not bad_phones and not bad_urls, "ungrounded_phones": bad_phones, "ungrounded_urls": bad_urls}
