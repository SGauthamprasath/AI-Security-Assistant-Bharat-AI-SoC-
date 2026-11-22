"""Explainable rule layer for scam SMS / chat messages (India-centred, English + Hinglish).

Rules do two jobs:
  * give the *reasons* shown to non-experts (every rule has a plain-language description), and
  * add a small, fitted log-odds nudge on top of the ML model (weights live in models/fusion.json;
    the numbers below are the priors that the fitting starts from).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

I = re.IGNORECASE

# id -> (regex, prior weight, plain-language description, scam category, remediation ids)
_R = {}


def _rule(rid, pattern, w, desc, cat, rem=(), neg=None):
    _R[rid] = (re.compile(pattern, I), w, desc, cat, tuple(rem), re.compile(neg, I) if neg else None)


_rule("S_ACCOUNT_THREAT",
      r"(account|a/c|card|sim|mobile number|number|service|wallet|upi|net ?banking|connection).{0,45}(block(ed)?|suspend(ed)?|deactivat\w+|disconnect\w*|freez\w+|restrict\w*|clos(e|ed|ure)|terminat\w+|expire[sd]?)",
      1.1, "It threatens that your account, card or SIM will be blocked or closed.", "account_threat",
      ("DONT_OPEN_LINK", "VERIFY_OFFICIAL_CHANNEL"))
_rule("S_URGENCY",
      r"within\s+(the\s+)?(next\s+)?\d+\s*(hours?|hrs?|mins?|minutes?)|immediately|today only|last (warning|chance|notice|reminder)|expires? (today|tonight)|\burgent(ly)?\b|right now|without delay|act now|failing which|final notice",
      0.6, "It pressures you to act immediately.", "pressure", ())
_rule("S_KYC_UPDATE",
      r"(e-?kyc|\bkyc\b|\bpan\b|aadhaa?r|pan card|re-?kyc).{0,60}(updat|verif|expir|pending|suspend|block|complet|link)|(updat|verif|complet)\w*.{0,40}(\bkyc\b|\bpan\b|aadhaa?r)",
      1.3, "It asks you to update or verify KYC / PAN / Aadhaar, a very common bank-scam pretext.", "bank_kyc",
      ("DONT_OPEN_LINK", "VERIFY_OFFICIAL_CHANNEL", "REPORT_1930"))
_rule("S_ASK_CREDENTIALS",
      r"(share|send|enter|provide|submit|tell|give|confirm|reply with|type)\W+(?:\w+\W+){0,4}(otp|pin|cvv|cvc|password|passcode|card (number|details|no)|upi pin|atm pin|expiry|mpin|net ?banking (id|password|credentials))",
      1.7, "It asks for a secret (OTP, PIN, CVV or password). Banks never ask for these.", "credential_theft",
      ("NEVER_SHARE_CREDENTIALS", "DELETE_MESSAGE", "REPORT_1930"),
      neg=r"(do not|don't|dont|never|not to|won't|will not|shall not|nobody|no one|anyone|any one|else)\W+(?:\w+\W+){0,3}$")
_rule("S_REWARD",
      r"you (have |'ve )?(won|win|been selected|are selected|are the winner)|congratulations.{0,60}(won|winner|prize|reward|cashback|lucky|gift|selected for (a |the )?(gift|reward|prize|offer))|lucky (draw|winner|customer)|\bkbc\b|jackpot|prize (money|amount)|reward points? (expire|will)|claim (your )?(gift|reward|prize|cashback|bonus)|redeem (your )?(points|reward|gift)|free (iphone|gift|recharge|gold)",
      1.3, "It says you have won a prize or reward you never applied for.", "reward_lottery",
      ("DONT_OPEN_LINK", "DELETE_MESSAGE"))
_rule("S_JOB_TASK",
      r"(part[- ]?time|work from home|wfh|online (job|work)|earn).{0,50}(daily|per day|everyday|weekly|monthly|\d+\s?k\b|amttok|rs)|(telegram|whatsapp).{0,40}(task|job|group|channel|hr)|(like|subscribe|rate).{0,20}(youtube|videos?|hotels?|products?).{0,40}(earn|paid|commission)|(?:salary|income).{0,20}(daily|guaranteed)",
      1.5, "It offers easy money for simple online tasks, a classic task/job scam.", "job_task_scam",
      ("DELETE_MESSAGE", "DONT_PAY_ADVANCE", "REPORT_1930"))
_rule("S_DELIVERY_PROBLEM",
      r"(parcel|package|shipment|courier|consignment|delivery|order).{0,70}(held|on hold|pending|failed|unable to deliver|address (is )?(incomplete|incorrect|invalid)|customs|redeliver|reschedule|storage fee|clearance)|(pay|payment of).{0,30}(customs|delivery|redelivery|clearance|handling) (fee|charge)",
      1.1, "It claims a parcel is stuck and asks for action or a fee, a common delivery scam.", "delivery_scam",
      ("DONT_OPEN_LINK", "VERIFY_OFFICIAL_CHANNEL"))
_rule("S_UTILITY_CUT",
      r"(electricity|power|gas|water|broadband|dth|fastag|challan).{0,60}(disconnect\w*|cut|tonight|suspend\w*|overdue|unpaid|pending bill|penalty)|(last date|bill).{0,40}(tonight|9:?30|disconnect)",
      1.3, "It threatens to cut off electricity, gas or another utility unless you act now.", "utility_scam",
      ("DONT_OPEN_LINK", "VERIFY_OFFICIAL_CHANNEL"))
_rule("S_AUTHORITY_ARREST",
      r"(cbi|enforcement directorate|\bed\b|police|customs|narcotics|\bncb\b|trai|rbi|income tax|cyber ?crime|court|supreme court|fedex|dhl).{0,120}(arrest|warrant|illegal|drugs|money laundering|fir\b|case (has been|is) (filed|registered)|legal action|prosecut|seiz)|digital arrest|your (aadhaa?r|sim|number|bank account) (is|has been) (linked|used|involved|misused)",
      2.0, "It pretends to be police / a government agency and threatens arrest or legal action.", "authority_impersonation",
      ("DONT_CALL_BACK", "REPORT_1930", "VERIFY_OFFICIAL_CHANNEL"))
_rule("S_REMOTE_ACCESS",
      r"anydesk|team ?viewer|quick ?support|airdroid|rustdesk|ultraviewer|\.apk\b|install (the |this )?(app|application)|download (the |this )?(app|apk|application)|screen ?share",
      1.8, "It asks you to install an app or give remote access to your phone.", "remote_access_scam",
      ("DONT_INSTALL_APK", "REPORT_1930"))
_rule("S_INVESTMENT",
      r"(guarantee[d]?|assured|risk[- ]?free|fixed).{0,40}(return|profit|income|gain)|double your (money|investment)|\bcrypto\b|\busdt\b|bitcoin|trading (group|signals?|tips?)|stock (tips?|group)|ipo (allotment|group)|vip (group|tips)|\d+\s?%\s*(return|profit|daily|weekly)",
      1.4, "It promises guaranteed or very high investment returns.", "investment_scam",
      ("DONT_PAY_ADVANCE", "DELETE_MESSAGE", "REPORT_1930"))
_rule("S_LOAN_OFFER",
      r"(pre-?approved|instant|easy|quick).{0,25}loan.{0,70}(no (document|cibil|collateral|income)|apply now|click|link|processing fee)|loan (is )?(approved|sanctioned).{0,60}(processing fee|pay|click|link)",
      1.1, "It offers an instant loan and asks for a fee or a link click first.", "loan_scam",
      ("DONT_PAY_ADVANCE", "DELETE_MESSAGE"))
_rule("S_UPI_COLLECT",
      r"collect request|(scan|use) (the |this )?qr( code)?.{0,40}(receive|get|refund|claim|money)|(to )?receive (the )?(money|payment|refund|cashback).{0,40}(pin|scan|approve|accept)|accept the (request|collect)",
      1.6, "It asks you to enter a UPI PIN or scan a code 'to receive' money. You only enter a PIN to PAY.", "upi_scam",
      ("NEVER_SHARE_CREDENTIALS", "DELETE_MESSAGE", "REPORT_1930"))
_rule("S_HEY_MUM",
      r"(hi|hello|hey)?\s*(mum|mom|dad|papa|mummy|maa)\W.{0,60}(new number|lost my phone|phone (is )?(broken|dead|damaged|stolen)|dropped my phone|this is my new)",
      1.8, "It pretends to be a family member on a 'new number' and will soon ask for money.", "family_impersonation",
      ("VERIFY_OFFICIAL_CHANNEL", "DONT_PAY_ADVANCE"))
_rule("S_REFUND_TAX",
      r"(refund|rebate|cashback|tax).{0,40}(approved|pending|credited|processed|ready|eligible).{0,80}(click|link|verify|update|urltok|claim)",
      1.3, "It says a refund is waiting for you but asks you to click a link first.", "refund_scam",
      ("DONT_OPEN_LINK", "VERIFY_OFFICIAL_CHANNEL"))
_rule("S_CLICK_LINK",
      r"(click|tap|visit|open|login|log in|sign in|update|verify|download|claim|check)\W+(?:\w+\W+){0,4}(link|urltok|here|below|now)",
      0.5, "It tells you to click a link.", "link_lure", ("DONT_OPEN_LINK",))
_rule("S_CALL_BACK",
      r"(call|contact|whatsapp|dial|reach)\W+(?:\w+\W+){0,4}(phonetok|customer care|helpline|support|officer|immediately)",
      0.6, "It asks you to call an unknown number straight away.", "callback_lure", ("DONT_CALL_BACK",))
_rule("S_GENERIC_GREETING",
      r"^(dear|hello|hi)\W+(customer|user|sir|madam|valued|account holder|bank user|client|member|winner)",
      0.3, "It uses a generic greeting instead of your name.", "generic", ())

# --- legitimate-looking patterns (negative evidence) -------------------------------------------
_rule("L_OTP_NOTICE",
      r"(is|are) (your|the) (otp|one[- ]time password|verification code|login code|code)|(otp|code) (for|to) (login|transaction|verify|your|payment|reset)|(do not|don't|dont|never) share (this |your |the )?(otp|code|pin|password|cvv)|\bvalid (for|till|upto)\b|expires? in \d+ ?(min|minutes)",
      -1.5, "It looks like a normal one-time-code message that warns you not to share the code.", "legit_otp", ("NO_ACTION_NEEDED",))
_rule("L_TXN_ALERT",
      r"(debited|credited|spent|withdrawn|received|paid|sent).{0,50}(a/c|acct|account|card|upi|wallet).{0,40}(numtok|xx|x{2,}|\*{2,})|(avl|available|avail|closing) ?(bal|balance)|\bbal(ance)?\b.{0,10}amttok|(a/c|account|card) (no\.? )?(ending|xx)",
      -1.3, "It looks like a normal transaction alert with no request for action.", "legit_txn", ("NO_ACTION_NEEDED",))
_rule("L_REFERENCE_IDS",
      r"\bupi ref|\butr\b|txn (id|no)|transaction (id|ref)|ref(erence)? (no|number|id)|order (id|no|number)|\bpnr\b|booking id",
      -0.8, "It carries a transaction / booking reference number like genuine service messages.", "legit_ref", ())
_rule("L_ORDER_STATUS",
      r"(your|ur) (order|booking|ticket|pnr|appointment|flight|train|ride|cab|slot|reservation|prescription|test report).{0,45}(confirmed|shipped|delivered|dispatched|scheduled|out for delivery|is ready|has been (booked|placed|received))|(thank you|thanks) for (shopping|booking|ordering|choosing|banking|your payment|recharging)|your .{0,20}(recharge|payment|bill) of.{0,20}(was |is )?(successful|received|processed)",
      -1.0, "It looks like an ordinary order / booking / payment confirmation.", "legit_order", ("NO_ACTION_NEEDED",))
_rule("L_VISIT_BRANCH",
      r"(visit|contact|approach)( your| the| nearest)?( home)? (branch|bank branch)|(mobile|net ?banking) app (or|/)|do not (click|tap) (on )?(any )?links?|(never|don't|do not) (click|tap).{0,25}link",
      -1.0, "It sends you to a branch or the official app instead of a link, which is how real banks write.", "legit_branch", ("NO_ACTION_NEEDED",))
_rule("L_DELIVERY_OTP",
      r"delivery (otp|code|pin)|(share|give|tell|hand) (it|this|the (otp|code|pin)).{0,25}(delivery|rider|agent|associate|executive|partner)|(delivery|rider|agent|associate|executive|partner).{0,25}(only )?(after|on|upon) (receiving|delivery|handing)",
      -1.1, "It is a delivery hand-over code, to be shared only with the courier at your door.", "legit_delivery_otp", ("NO_ACTION_NEEDED",))
_rule("L_APPOINTMENT_REMINDER",
      r"(reminder|appointment|scheduled|meeting|class|exam|lecture|fees? (due|receipt)|parent[- ]teacher).{0,60}(tomorrow|today|at datetok|on datetok|datetok)",
      -0.6, "It looks like an ordinary appointment / schedule reminder.", "legit_reminder", ())

SMS_RULES = {k: dict(rx=v[0], weight=v[1], desc=v[2], category=v[3], remediation=v[4], neg=v[5]) for k, v in _R.items()}

# Banks / brands for the sender-ID consistency check (Indian SMS headers look like "VM-HDFCBK", "AX-SBIINB")
_BRAND_IN_TEXT = re.compile(r"\b(sbi|state bank|hdfc|icici|axis|kotak|pnb|paytm|phonepe|google pay|gpay|amazon|flipkart|irctc|epfo|uidai|aadhaa?r|income tax|airtel|jio|vodafone|\bvi\b|bsnl|fedex|dhl|india post)\b", I)
_ALNUM_HEADER = re.compile(r"^[A-Z]{2}-[A-Z0-9]{3,8}$|^[A-Z][A-Z0-9\-]{4,10}$")
_PLAIN_NUMBER = re.compile(r"^\+?\d[\d\s\-]{6,}$")
SENDER_RULE = ("S_SENDER_MISMATCH", 1.4, "It claims to be a bank or brand but came from an ordinary mobile number, not a verified sender name.", "sender_mismatch", ("DONT_CALL_BACK", "VERIFY_OFFICIAL_CHANNEL"))


def sms_rule_hits(raw_text: str, norm_text: str, sender: Optional[str] = None) -> List[Dict[str, str]]:
    """Return [{'id', 'match', 'category', 'description', 'prior_weight'}] for every rule that fires.

    Rules run on the *normalised* text (urls -> 'urltok', numbers -> 'numtok' ...) so that
    the same patterns work on anonymised training data and on real messages.
    """
    hits = []
    t = norm_text
    for rid, r in SMS_RULES.items():
        for m in r["rx"].finditer(t):
            if r["neg"] is not None and r["neg"].search(t[max(0, m.start() - 40): m.start()]):
                continue  # e.g. "do not SHARE your otp" is a warning, not a request
            hits.append({"id": rid, "match": m.group(0)[:40], "category": r["category"],
                         "description": r["desc"], "prior_weight": r["weight"]})
            break
    if sender and _BRAND_IN_TEXT.search(raw_text):
        s = sender.strip()
        if _PLAIN_NUMBER.match(s) and not _ALNUM_HEADER.match(s.upper()):
            hits.append({"id": SENDER_RULE[0], "match": s, "category": SENDER_RULE[3],
                         "description": SENDER_RULE[2], "prior_weight": SENDER_RULE[1]})
    return hits


def rule_ids() -> List[str]:
    return list(SMS_RULES.keys()) + [SENDER_RULE[0]]


def prior_weights() -> Dict[str, float]:
    d = {k: v["weight"] for k, v in SMS_RULES.items()}
    d[SENDER_RULE[0]] = SENDER_RULE[1]
    return d
