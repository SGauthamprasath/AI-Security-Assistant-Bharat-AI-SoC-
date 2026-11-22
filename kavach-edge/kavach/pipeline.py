"""The Kavach-Edge detector: message / URL / network-traffic  ->  evidence JSON.

    detector = Detector()
    ev = detector.analyze_message("Dear SBI user your account is blocked ... http://sbi-kyc.xyz", sender="+9198...")
    ev = detector.analyze_url("https://hdfc-secure.top/login")
    res = detector.analyze_pcap("capture.pcap")      # {"summary": ..., "alerts": [evidence, ...]}

Everything runs locally; the only third-party import on the hot path is NumPy.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import time
import uuid
from collections import Counter
from typing import Dict, List, Optional, Sequence

import numpy as np

from . import SCHEMA_VERSION, __version__, advisor, fusion, netkit, sms_rules, textnorm, urlkit
from .sms_model import SmsModel
from .url_model import UrlModel


def _ms(t0: int) -> float:
    return (time.perf_counter_ns() - t0) / 1e6


def _conf(p: float, th: Dict[str, float]) -> str:
    if p >= max(th["dangerous"], 0.0) and p >= 0.9 or p <= 0.03:
        return "high"
    if abs(p - th["suspicious"]) < 0.08 or abs(p - th["dangerous"]) < 0.05:
        return "low"
    return "medium"


class Detector:
    def __init__(self, load_net: bool = True, model_dir: Optional[str] = None):
        t0 = time.perf_counter_ns()
        kw = {"model_dir": model_dir} if model_dir else {}
        self.sms = SmsModel(**kw)
        self.url = UrlModel(**kw)
        self.net = netkit.NetModel(**kw) if load_net else None
        self.fusion = fusion.Fusion()
        urlkit._trusted()  # warm caches so first inference is not penalised
        urlkit._psl_multi()
        self.load_ms = _ms(t0)

    # ------------------------------------------------------------------ helpers
    def model_footprint(self) -> Dict[str, int]:
        d = {"sms_model_bytes": self.sms.size_bytes, "url_model_bytes": self.url.size_bytes}
        if self.net:
            d["net_model_bytes"] = self.net.size_bytes
        return d

    def _privacy(self) -> Dict[str, object]:
        return {"processed_on_device": True, "network_calls": 0, "raw_text_included": False, "max_snippet_chars": 40, "detector_version": __version__}

    def _url_entities(self, urls: Sequence[str]):
        out, z, hits = [], [], []
        for u in urls:
            p = urlkit.parse_url(u)
            host = str(p["host"])
            if not host:
                continue
            sc = self.url.score_host(host)
            hh = urlkit.url_rule_hits(u)
            sub, reg, suf = urlkit.registered_domain(host)
            z.append(sc["logit"])
            hits.append([h[0] for h in hh])
            out.append({"url": u[:120], "host": host, "registered_domain": reg, "model_p_phish": round(sc["p"], 4),
                        "flags": [h[0] for h in hh if h[0] not in fusion.URL_TRUST_IDS], "trust": [h[0] for h in hh if h[0] in fusion.URL_TRUST_IDS],
                        "details": {h[0]: h[1] for h in hh}})
        return out, z, hits

    @staticmethod
    def _sender_type(sender: Optional[str]) -> str:
        if not sender:
            return "unknown"
        return "number" if sms_rules._PLAIN_NUMBER.match(sender.strip()) else "alphanumeric"

    # ------------------------------------------------------------------ message
    def analyze_message(self, text: str, sender: Optional[str] = None, with_prompt: bool = True, language: str = "en") -> Dict:
        T0 = time.perf_counter_ns()
        st: Dict[str, float] = {}
        t = time.perf_counter_ns()
        norm = textnorm.normalize_sms(text)
        urls = textnorm.extract_urls(text)
        st["preprocess"] = _ms(t)

        t = time.perf_counter_ns()
        sms = self.sms.score(text)
        st["sms_model"] = _ms(t)

        t = time.perf_counter_ns()
        sms_hits = sms_rules.sms_rule_hits(text, norm, sender)
        st["sms_rules"] = _ms(t)

        t = time.perf_counter_ns()
        url_ents, url_z, url_hits = self._url_entities(urls)
        st["url_analysis"] = _ms(t)

        t = time.perf_counter_ns()
        vec = fusion.message_vector(sms["logit"], url_z, [h["id"] for h in sms_hits], url_hits)
        z = self.fusion.message_logit(vec)
        p = float(fusion.sigmoid(z))
        band = self.fusion.band(p, "message")
        contrib = self.fusion.contributions(vec, "message")
        st["fusion"] = _ms(t)

        t = time.perf_counter_ns()
        ev = self._build_message_evidence(text, sender, sms, sms_hits, url_ents, contrib, p, band)
        st["evidence"] = _ms(t)
        if with_prompt:
            t = time.perf_counter_ns()
            ev["advisor_prompt"] = advisor.build_prompt(ev, language)
            st["prompt"] = _ms(t)
        ev["performance"] = {"total_ms": round(_ms(T0), 3), "stage_ms": {k: round(v, 3) for k, v in st.items()}}
        return ev

    def _build_message_evidence(self, text, sender, sms, sms_hits, url_ents, contrib, p, band) -> Dict:
        th = self.fusion.th["message"]
        rule_by_id = {h["id"]: h for h in sms_hits}
        signals = []
        for name, c in sorted(contrib, key=lambda kv: -abs(kv[1])):
            if name == "z_sms":
                toks = self.sms.top_tokens(text) if c > 0.3 else []
                signals.append({"id": "M_TEXT_MODEL", "source": "model", "modality": "sms", "direction": "risk" if c > 0 else "reassuring",
                                "contribution": round(c, 3), "description": ("The wording closely matches known scam messages." if c > 0 else "The wording looks like an ordinary legitimate message."),
                                "match": ", ".join(w for w, _ in toks[:4]) or None})
            elif name == "z_url":
                worst = max(url_ents, key=lambda u: u["model_p_phish"]) if url_ents else None
                signals.append({"id": "M_URL_MODEL", "source": "model", "modality": "url", "direction": "risk" if c > 0 else "reassuring",
                                "contribution": round(c, 3), "description": ("The website address looks like those used in phishing." if c > 0 else "The website address looks like a normal site."),
                                "match": worst["host"] if worst else None})
            elif name == "has_url":
                continue
            elif name in rule_by_id:
                h = rule_by_id[name]
                signals.append({"id": name, "source": "rule", "modality": "sms", "direction": "risk" if c > 0 else "reassuring", "contribution": round(c, 3),
                                "description": h["description"], "match": h["match"]})
            elif name in urlkit.URL_RULES:
                det = next((u["details"].get(name) for u in url_ents if name in u["details"]), None)
                signals.append({"id": name, "source": "rule", "modality": "url", "direction": "risk" if c > 0 else "reassuring", "contribution": round(c, 3),
                                "description": urlkit.URL_RULES[name][1], "match": det})
        cat = "generic"
        weak = {"link_lure", "generic", "pressure", "callback_lure"}
        risk_rules = [s for s in signals if s["direction"] == "risk" and s["source"] == "rule"]
        sms_cat = [s for s in risk_rules if s["id"] in sms_rules.SMS_RULES and sms_rules.SMS_RULES[s["id"]]["category"] not in weak]
        if sms_cat:
            cat = sms_rules.SMS_RULES[sms_cat[0]["id"]]["category"]
        elif any(s["id"] == "S_SENDER_MISMATCH" for s in risk_rules):
            cat = "sender_mismatch"
        elif any(s["id"] == "U_APK_DOWNLOAD" for s in risk_rules):
            cat = "remote_access_scam"
        elif any(s["id"] in urlkit.URL_RULES for s in risk_rules):
            cat = "phishing_url"
        elif risk_rules:
            cat = sms_rules.SMS_RULES.get(risk_rules[0]["id"], {"category": "generic"})["category"]
        rem = self._remediation(band, signals, bool(url_ents))
        return {
            "schema_version": SCHEMA_VERSION, "event_id": str(uuid.uuid4()),
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "input": {"type": "sms", "sha256": hashlib.sha256(text.encode()).hexdigest()[:32], "length": len(text), "sender_type": self._sender_type(sender)},
            "verdict": {"label": band, "risk_score": round(p, 4), "confidence": _conf(p, th), "thresholds": {k: round(v, 4) for k, v in th.items()}},
            "category": cat, "category_text": advisor.CATEGORY_TEXT.get(cat, advisor.CATEGORY_TEXT["generic"]),
            "signals": signals,
            "model_outputs": {"sms": {"p_scam": round(sms["p"], 4)}, "urls": [{"host": u["host"], "p_phish": u["model_p_phish"]} for u in url_ents]},
            "entities": {"urls": url_ents, "has_phone_number": "phonetok" in textnorm.normalize_sms(text)},
            "remediation": rem, "privacy": self._privacy(),
        }

    def _remediation(self, band: str, signals: List[Dict], has_url: bool) -> List[str]:
        if band == "safe":
            return ["NO_ACTION_NEEDED"]
        rem: List[str] = []

        def add(x):
            if x not in rem:
                rem.append(x)
        for s in signals:
            if s["direction"] != "risk" or s["source"] != "rule":
                continue
            if s["id"] in sms_rules.SMS_RULES:
                r = sms_rules.SMS_RULES[s["id"]]["remediation"]
            elif s["id"] == "S_SENDER_MISMATCH":
                r = sms_rules.SENDER_RULE[4]
            else:
                r = urlkit.URL_RULES[s["id"]][2]
            for a in r:
                add(a)
        if has_url:
            add("DONT_OPEN_LINK")
        if band == "dangerous":
            add("DELETE_MESSAGE"); add("BLOCK_SENDER")
        add("IF_ALREADY_CLICKED")
        pri = {"NEVER_SHARE_CREDENTIALS": 0, "DONT_OPEN_LINK": 1, "DONT_INSTALL_APK": 1, "DONT_CALL_BACK": 2, "DONT_PAY_ADVANCE": 2, "VERIFY_OFFICIAL_CHANNEL": 3,
               "DELETE_MESSAGE": 4, "BLOCK_SENDER": 5, "REPORT_1930": 6, "IF_ALREADY_CLICKED": 7}
        rem.sort(key=lambda a: pri.get(a, 9))
        return rem[:6]

    # ------------------------------------------------------------------ url
    def analyze_url(self, url: str, with_prompt: bool = True, language: str = "en") -> Dict:
        T0 = time.perf_counter_ns()
        st: Dict[str, float] = {}
        t = time.perf_counter_ns()
        ents, zs, hits = self._url_entities([url])
        st["url_analysis"] = _ms(t)
        if not ents:
            raise ValueError("could not parse a host from the url")
        vec = fusion.url_vector(zs[0], hits[0])
        z = self.fusion.url_logit(vec)
        p = float(fusion.sigmoid(z))
        band = self.fusion.band(p, "url")
        th = self.fusion.th["url"]
        signals = []
        for name, c in sorted(self.fusion.contributions(vec, "url"), key=lambda kv: -abs(kv[1])):
            if name == "z_url":
                signals.append({"id": "M_URL_MODEL", "source": "model", "modality": "url", "direction": "risk" if c > 0 else "reassuring", "contribution": round(c, 3),
                                "description": ("The website address looks like those used in phishing." if c > 0 else "The website address looks like a normal site."), "match": ents[0]["host"]})
            else:
                signals.append({"id": name, "source": "rule", "modality": "url", "direction": "risk" if c > 0 else "reassuring", "contribution": round(c, 3),
                                "description": urlkit.URL_RULES[name][1], "match": ents[0]["details"].get(name)})
        cat = "phishing_url"
        if any(s["id"] == "U_APK_DOWNLOAD" and s["direction"] == "risk" for s in signals):
            cat = "remote_access_scam"
        rem = ["NO_ACTION_NEEDED"] if band == "safe" else None
        if rem is None:
            rem = []
            for s in signals:
                if s["direction"] == "risk" and s["source"] == "rule":
                    for a in urlkit.URL_RULES[s["id"]][2]:
                        if a not in rem:
                            rem.append(a)
            for a in ("DONT_OPEN_LINK", "IF_ALREADY_CLICKED"):
                if a not in rem:
                    rem.append(a)
            if band == "dangerous" and "REPORT_1930" not in rem:
                rem.insert(-1, "REPORT_1930")
        ev = {"schema_version": SCHEMA_VERSION, "event_id": str(uuid.uuid4()), "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
              "input": {"type": "url", "sha256": hashlib.sha256(url.encode()).hexdigest()[:32], "length": len(url), "sender_type": "unknown"},
              "verdict": {"label": band, "risk_score": round(p, 4), "confidence": _conf(p, th), "thresholds": {k: round(v, 4) for k, v in th.items()}},
              "category": cat, "category_text": advisor.CATEGORY_TEXT[cat], "signals": signals,
              "model_outputs": {"urls": [{"host": ents[0]["host"], "p_phish": ents[0]["model_p_phish"]}]},
              "entities": {"urls": ents, "has_phone_number": False}, "remediation": rem, "privacy": self._privacy()}
        if with_prompt:
            ev["advisor_prompt"] = advisor.build_prompt(ev, language)
        ev["performance"] = {"total_ms": round(_ms(T0), 3), "stage_ms": {k: round(v, 3) for k, v in st.items()}}
        return ev

    # ------------------------------------------------------------------ network
    def analyze_rows(self, rows: List[Dict], with_prompt: bool = True) -> Dict:
        """rows = netflow.conn_features(...) output.  Returns {"summary":..., "alerts":[evidence,...]}."""
        from . import netflow

        T0 = time.perf_counter_ns()
        if not rows:
            return {"summary": {"connections": 0, "flagged": 0}, "alerts": []}
        X = np.vstack([netkit.encode_row(r, self.net.meta) for r in rows])
        out = self.net.predict(X)
        nf = self.net_cfg()
        z = out["logit"].copy()
        row_hits = [netflow.row_rule_hits(r) for r in rows]
        for i, hh in enumerate(row_hits):
            z[i] += min(nf["rule_cap"], sum(nf["rule_weight"] * netflow.NET_RULES[h][0] / 2.2 for h in hh))
        p = fusion.sigmoid(z)
        th = self.fusion.th["network"]
        flagged = np.where(p >= th["suspicious"])[0]
        alerts = self._group_alerts(rows, flagged, p, out["proba"], row_hits, th, with_prompt)
        summary = {"connections": len(rows), "flagged": int(len(flagged)), "alerts": len(alerts),
                   "flag_rate": round(len(flagged) / len(rows), 4), "analysis_ms": round(_ms(T0), 2)}
        return {"summary": summary, "alerts": alerts}

    def net_cfg(self):
        return self.fusion.net

    def analyze_pcap(self, path: str, with_prompt: bool = True) -> Dict:
        from . import netflow

        t = time.perf_counter_ns()
        conns = netflow.read_pcap(path)
        rows = netflow.conn_features(conns)
        res = self.analyze_rows(rows, with_prompt)
        res["summary"]["parse_ms"] = round(_ms(t) - res["summary"]["analysis_ms"], 2)
        return res

    def _group_alerts(self, rows, flagged, p, proba, row_hits, th, with_prompt) -> List[Dict]:
        groups: Dict[tuple, List[int]] = {}
        for i in flagged:
            r = rows[i]
            beh = "icmp" if r["protocol_type"] == "icmp" else ("syn" if r["flag"] in ("S0", "S1", "S2", "S3") else ("reject" if r["flag"] in ("REJ", "RSTO", "RSTOS0", "RSTR") else "other"))
            groups.setdefault((r["_dst"], beh), []).append(int(i))
        alerts = []
        for (dst, _beh), idxs in groups.items():
            rs = [rows[i] for i in idxs]
            if len(idxs) < 3:
                continue
            srcs = Counter(r["_src"] for r in rs)
            ports = {r["_dport"] for r in rs}
            protos = Counter(r["protocol_type"] for r in rs)
            flags = Counter(r["flag"] for r in rs)
            dur = max(r["_t0"] for r in rs) - min(r["_t0"] for r in rs)
            votes = Counter(netkit.CLASSES[int(proba[i].argmax())] for i in idxs)
            rule_votes = Counter(h for i in idxs for h in row_hits[i])
            n = len(idxs)
            if protos.get("icmp", 0) / n > 0.6:
                kind, label = "dos", "ping flood" if len(srcs) <= 3 else "ICMP echo-reply flood (smurf-like)"
            elif len(ports) >= 20 and len(srcs) <= 3:
                kind, label = "probe", "port scan"
            elif flags.get("S0", 0) / n > 0.8 and n >= 50:
                kind, label = "dos", "SYN flood" + (" from many (possibly spoofed) addresses" if len(srcs) > 20 else "")
            else:
                kind = [k for k, _ in votes.most_common() if k != "normal"][0] if any(k != "normal" for k in votes) else "probe"
                label = netkit.EXPLAIN.get(kind, ("suspicious traffic",))[0]
            pm = float(np.mean([p[i] for i in idxs]))
            band = "dangerous" if pm >= th["dangerous"] and n >= 10 else "suspicious"
            title, plain, rem = netkit.EXPLAIN.get(kind, ("Suspicious traffic", "Unusual network activity.", ("ISOLATE_DEVICE",)))
            signals = [{"id": "M_NET_MODEL", "source": "model", "modality": "network", "direction": "risk", "contribution": round(float(np.mean([np.log(p[i] / (1 - p[i] + 1e-9)) for i in idxs])), 3),
                        "description": f"The traffic pattern matches known {kind.upper()} attacks in the training data.", "match": f"{n} connections"}]
            for rid, cnt in rule_votes.most_common():
                signals.append({"id": rid, "source": "rule", "modality": "network", "direction": "risk", "contribution": round(self.net_cfg()["rule_weight"] * 2.2, 3),
                                "description": __import__("kavach.netflow", fromlist=["x"]).NET_RULES[rid][1], "match": f"{cnt} of {n} connections"})
            ev = {"schema_version": SCHEMA_VERSION, "event_id": str(uuid.uuid4()), "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                  "input": {"type": "flow_window", "sha256": hashlib.sha256(f"{dst}{n}{dur}".encode()).hexdigest()[:32], "length": n, "sender_type": "unknown"},
                  "verdict": {"label": band, "risk_score": round(pm, 4), "confidence": "high" if pm > 0.9 else "medium", "thresholds": {k: round(v, 4) for k, v in th.items()}},
                  "category": kind, "category_text": f"{label}", "signals": signals,
                  "model_outputs": {"net": {"mean_p_attack": round(pm, 4), "class_votes": dict(votes)}},
                  "entities": {"src_ips": [s for s, _ in srcs.most_common(3)], "n_sources": len(srcs), "dst_ip": dst, "n_connections": n, "distinct_ports": len(ports),
                               "protocols": dict(protos), "tcp_flag_mix": dict(flags), "duration_s": round(dur, 2), "urls": [], "has_phone_number": False},
                  "remediation": list(rem) + (["RESTART_ROUTER"] if kind == "dos" and "RESTART_ROUTER" not in rem else []), "privacy": self._privacy()}
            ev["plain_summary"] = plain
            if with_prompt:
                ev["advisor_prompt"] = advisor.build_prompt(ev)
            alerts.append(ev)
        alerts.sort(key=lambda e: -e["verdict"]["risk_score"])
        return alerts
