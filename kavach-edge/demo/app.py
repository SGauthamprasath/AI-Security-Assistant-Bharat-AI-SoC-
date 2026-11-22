#!/usr/bin/env python3
"""Offline demo UI (stdlib only).  python3 demo/app.py  ->  http://127.0.0.1:8000   (works in airplane mode, also on Termux)

The server listens on loopback only and makes no outbound connection: it exists purely so a phone/laptop browser can talk to the detector
running in the same device. Endpoints: POST /api/message {text,sender,lang}  POST /api/url {url,lang}  GET /api/pcaps  GET /api/pcap?name=port_scan&lang=en
Explanations come from the deterministic template explainer; if you integrate the on-device LLM, call it with ev['advisor_prompt'] and verify it with
advisor.check_grounding() before showing it (see README, "Advisor integration").
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kavach import advisor  # noqa: E402
from kavach.pipeline import Detector  # noqa: E402

DET = Detector()
PCAPS = os.path.join(ROOT, "demo", "pcaps")

PAGE = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Kavach-Edge</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#fbfaf7;color:#0b0b0b}main{max-width:820px;margin:auto;padding:16px}
textarea,input,select{width:100%;font:inherit;padding:8px;border:1px solid #e4e3df;border-radius:8px;box-sizing:border-box}button{font:inherit;padding:9px 18px;border:0;border-radius:8px;background:#2a78d6;color:#fff;font-weight:600;cursor:pointer;margin:6px 6px 6px 0}
.card{background:#fff;border:1px solid #e4e3df;border-radius:12px;padding:14px;margin:12px 0}.badge{display:inline-block;color:#fff;padding:3px 12px;border-radius:99px;font-weight:700}
.dangerous{background:#c0392b}.suspicious{background:#b7791f}.safe{background:#1a7f4f}.bar{height:14px;border-radius:4px;margin:2px 0 8px}.risk{background:#c0392b}.ok{background:#1a7f4f}code{font-size:12px;color:#52514e}
.tag{font-size:13px;color:#52514e}</style></head><body><main><h1>Kavach-Edge <span class=tag>runs on this device - no network</span></h1>
<div class=card><b>Message</b><textarea id=t rows=3 placeholder="Paste an SMS / WhatsApp message"></textarea><input id=s placeholder="Sender (optional), e.g. VK-SBIYNO"><br>
<select id=lang style="width:auto"><option value=en>English</option><option value=hi>हिन्दी</option></select> <button onclick=msg()>Check message</button>
<button onclick=ex(0)>Example: scam</button><button onclick=ex(1)>Example: genuine OTP</button></div>
<div class=card><b>Link</b><input id=u placeholder="https://..."><button onclick=url()>Check link</button></div>
<div class=card><b>Network capture</b><select id=p></select><button onclick=pc()>Analyse capture</button></div><div id=out></div></main>
<script>
const EX=[["Dear SBI customer your YONO account will be blocked today. Update PAN now: http://sbi-yono-kyc.co/login","VK-SBIYNO"],["123456 is your OTP for login to your Bank account. Do not share it with anyone.","AX-HDFCBK"]];
const lang=()=>document.getElementById('lang').value;const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function ex(i){t.value=EX[i][0];s.value=EX[i][1];msg()}
async function post(p,b){const r=await fetch(p,{method:'POST',body:JSON.stringify(b)});return r.json()}
function show(ev,x){const v=ev.verdict;let h=`<div class=card><span class="badge ${v.label}">${esc(x.headline)}</span> <b>risk ${v.risk_score}</b> <span class=tag>(${v.confidence} confidence)</span><p>${esc(x.explanation)}</p>`;
 if(x.actions.length)h+='<b>What to do</b><ul>'+x.actions.map(a=>'<li>'+esc(a)+'</li>').join('')+'</ul>';
 const sg=(ev.signals||[]).slice(0,8),m=Math.max(...sg.map(z=>Math.abs(z.contribution)),1);
 h+='<details><summary>Evidence</summary>'+sg.map(z=>`<div><code>${esc(z.id)}</code> ${z.contribution>0?'+':''}${z.contribution}<div class="bar ${z.direction=='risk'?'risk':'ok'}" style="width:${Math.abs(z.contribution)/m*100}%"></div></div>`).join('')+'</details>';
 h+=`<details><summary>Evidence JSON (what an on-device LLM would receive)</summary><pre style="white-space:pre-wrap;font-size:12px">${esc(JSON.stringify(ev,null,1))}</pre></details></div>`;return h}
async function msg(){const r=await post('/api/message',{text:t.value,sender:s.value,lang:lang()});out.innerHTML=show(r.evidence,r.explanation)+`<span class=tag>${r.evidence.performance.total_ms} ms on this device</span>`}
async function url(){const r=await post('/api/url',{url:u.value,lang:lang()});out.innerHTML=r.error?'<div class=card>'+esc(r.error)+'</div>':show(r.evidence,r.explanation)}
async function pc(){const r=await (await fetch('/api/pcap?name='+p.value+'&lang='+lang())).json();let h=`<div class=card><b>${r.summary.connections}</b> connections, <b>${r.summary.flagged}</b> flagged</div>`;
 r.alerts.forEach((a,i)=>h+=show(a,r.explanations[i]));out.innerHTML=h||'<div class=card>No threats found.</div>'}
fetch('/api/pcaps').then(r=>r.json()).then(l=>p.innerHTML=l.map(n=>`<option>${n}</option>`).join(''));
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, obj, code=200, ctype="application/json"):
        body = obj.encode() if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            return self._send(PAGE, ctype="text/html")
        if u.path == "/api/pcaps":
            return self._send(sorted(f[:-5] for f in os.listdir(PCAPS) if f.endswith(".pcap")))
        if u.path == "/api/pcap":
            name = os.path.basename(q.get("name", [""])[0])
            path = os.path.join(PCAPS, name + ".pcap")
            if not os.path.exists(path):
                return self._send({"error": "unknown capture"}, 404)
            lang = q.get("lang", ["en"])[0]
            r = DET.analyze_pcap(path, with_prompt=False)
            return self._send({"summary": r["summary"], "alerts": r["alerts"], "explanations": [advisor.template_explanation(a, lang) for a in r["alerts"]]})
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        b = json.loads(self.rfile.read(n) or b"{}")
        lang = b.get("lang", "en")
        if self.path == "/api/message":
            ev = DET.analyze_message(b.get("text", ""), b.get("sender") or None, with_prompt=False, language=lang)
            return self._send({"evidence": ev, "explanation": advisor.template_explanation(ev, lang)})
        if self.path == "/api/url":
            try:
                ev = DET.analyze_url(b.get("url", ""), with_prompt=False, language=lang)
            except ValueError as e:
                return self._send({"error": str(e)})
            return self._send({"evidence": ev, "explanation": advisor.template_explanation(ev, lang)})
        self._send({"error": "not found"}, 404)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Kavach-Edge demo on http://127.0.0.1:{port}  (loopback only, no outbound network)")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
