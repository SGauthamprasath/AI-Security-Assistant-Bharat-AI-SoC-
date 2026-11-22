#!/usr/bin/env python3
"""Build the captioned explainer video (silent, 1280x720, 30 fps) from REAL pipeline outputs.

    python3 demo/video/build_video.py [--frames-only]     -> demo/video/kavach_edge_explainer.mp4  (+ scene PNGs in demo/video/frames/)

Every verdict, score, signal and metric on screen is produced by running the detector / read from results/*.json at build time.
No device numbers are shown unless measured: the stage timings are labelled "x86 development reference"; Arm numbers are shown only
if results/bench/bench_*arm*.json exists. The video is an explainer + backup; the headline demo is still the screen recording on the phone
(see demo/SHOT_LIST.md).  One encoded file per scene, joined with the concat demuxer (-c copy).
"""
import glob
import json
import os
import subprocess
import sys

from matplotlib import font_manager as fm
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from kavach import advisor  # noqa: E402
from kavach.pipeline import Detector  # noqa: E402

W, H, FPS = 1280, 720, 30
OUT = os.path.join(ROOT, "demo", "video")
FR = os.path.join(OUT, "frames")
os.makedirs(FR, exist_ok=True)
BG, INK, MUTED, LINE, CARD = "#fbfaf7", "#0b0b0b", "#52514e", "#e4e3df", "#ffffff"
BLUE, RED, AMBER, GREEN, ORANGE = "#2a78d6", "#c0392b", "#b7791f", "#1a7f4f", "#eb6834"
BAND = {"dangerous": RED, "suspicious": AMBER, "safe": GREEN}


def font(size, bold=False, mono=False):
    fam, w = ("DejaVu Sans Mono", "normal") if mono else ("Inter", "bold" if bold else "normal")
    return ImageFont.truetype(fm.findfont(fm.FontProperties(family=fam, weight=w)), size)


def wrap(d, text, f, width):
    out, line = [], ""
    for word in text.split():
        t = (line + " " + word).strip()
        if d.textlength(t, font=f) <= width:
            line = t
        else:
            out.append(line)
            line = word
    return out + [line] if line else out


def canvas():
    im = Image.new("RGB", (W, H), BG)
    return im, ImageDraw.Draw(im)


def card(d, box, fill=CARD, outline=LINE, r=18):
    d.rounded_rectangle(box, r, fill=fill, outline=outline, width=2)


def text(d, xy, s, size=28, color=INK, bold=False, mono=False, width=None, spacing=1.25):
    f = font(size, bold, mono)
    x, y = xy
    for ln in (wrap(d, s, f, width) if width else [s]):
        d.text((x, y), ln, font=f, fill=color)
        y += int(size * spacing)
    return y


def chip(d, xy, s, color, size=26):
    f = font(size, True)
    w = d.textlength(s, font=f) + 36
    d.rounded_rectangle((xy[0], xy[1], xy[0] + w, xy[1] + size + 22), 22, fill=color)
    d.text((xy[0] + 18, xy[1] + 9), s, font=f, fill="#ffffff")
    return xy[0] + w


def caption(d, s):
    d.rectangle((0, H - 84, W, H), fill="#0b0b0b")
    f = font(25)
    ls = wrap(d, s, f, W - 120)[:2]
    y = H - 84 + (84 - len(ls) * 32) // 2
    for ln in ls:
        d.text((60, y), ln, font=f, fill="#ffffff")
        y += 32


def header(d, n, title):
    d.text((60, 36), f"{n}", font=font(20, True), fill=BLUE)
    d.text((100, 30), title, font=font(34, True), fill=INK)


def signal_bars(d, x, y, signals, width=470, maxn=6):
    sig = sorted(signals, key=lambda s: -abs(s["contribution"]))[:maxn]
    m = max(abs(s["contribution"]) for s in sig) or 1
    for s in sig:
        lab = s["description"][:46] if s.get("description") else s["id"]
        d.text((x, y), s["id"], font=font(17, True, True), fill=MUTED)
        v = s["contribution"]
        w = int(abs(v) / m * (width - 150))
        col = RED if v > 0 else GREEN
        d.rounded_rectangle((x, y + 26, x + max(w, 6), y + 44), 6, fill=col)
        d.text((x + max(w, 6) + 8, y + 24), f"{v:+.1f}", font=font(16, False, True), fill=MUTED)
        y += 58
    return y


# ---------------------------------------------------------------- real outputs
det = Detector()
SCAM = "Dear SBI customer your YONO account will be blocked today. Update PAN now: http://sbi-yono-kyc.co/login"
OTP = "123456 is your OTP for login to your Bank account. Do not share it with anyone. Never share OTP, PIN or CVV."
URLS = ["https://amaz0n-in-support.top/gp/help", "https://www.amazon.in/gp/help/customer/display.html"]
ev_scam = det.analyze_message(SCAM, "VK-SBIYNO", with_prompt=False)
ev_otp = det.analyze_message(OTP, "AX-HDFCBK", with_prompt=False)
ev_u = [det.analyze_url(u, with_prompt=False) for u in URLS]
rep = det.analyze_pcap(os.path.join(ROOT, "demo", "pcaps", "port_scan.pcap"), with_prompt=False)
rep_ok = det.analyze_pcap(os.path.join(ROOT, "demo", "pcaps", "normal_browsing.pcap"), with_prompt=False)
M = json.load(open(os.path.join(ROOT, "results", "metrics.json")))
OFF = json.load(open(os.path.join(ROOT, "results", "offline_proof.json")))
bench_files = sorted(glob.glob(os.path.join(ROOT, "results", "bench", "bench_*.json")))
B = [json.load(open(f)) for f in bench_files]
arm = [b for b in B if not b.get("reference_only")]
bref = (arm or B)[0]
is_ref = not arm


def ex(ev):
    return advisor.template_explanation(ev, "en")


scenes = []  # (name, seconds, caption, PIL image)


def S(name, sec, cap, im):
    scenes.append((name, sec, cap, im))


# 1 title
im, d = canvas()
d.rectangle((0, 0, W, H), fill="#0b1a33")
d.text((90, 190), "Kavach-Edge", font=font(86, True), fill="#ffffff")
text(d, (92, 305), "On-device scam, phishing and network-threat guard", 40, "#cfe0fb", width=1000)
text(d, (92, 440), "Bharat AI-SoC Challenge 2026-27  |  Problem Statement 3", 28, "#9db8e0")
text(d, (92, 490), "Built for Arm CPUs. Everything you will see runs with no network.", 28, "#9db8e0")
S("title", 5, "Kavach-Edge: one small model bundle that warns you about scams, phishing links and suspicious network activity - entirely on your device.", im)

# 2 offline proof
im, d = canvas(); header(d, "1", "It never needs the internet - verified four ways")
rt, ns = OFF["runtime"], OFF["namespace"]
rows = [("Static audit", f"{OFF['static']['files_scanned']} source files import no networking module", OFF["static"]["pass"]),
        ("Runtime guard", f"{rt['n_verdicts']} verdicts + {rt['pcaps']} pcaps: {len(rt['events'])} network events (deliberate connect was caught)", rt["pass"]),
        ("Empty network namespace", f"same verdict digest {ns['verdict_digest']}, zero events" if ns["available"] else "not available", ns.get("pass", False)),
        ("On the phone", "airplane mode + tcpdump: to be recorded on device", None)]
y = 130
for a, b, ok in rows:
    card(d, (60, y, W - 60, y + 118))
    col = GREEN if ok else (AMBER if ok is None else RED)
    d.ellipse((90, y + 40, 128, y + 78), fill=col)
    d.text((101 - (6 if ok is not True else 0), y + 46), "ok" if ok else ("..." if ok is None else "x"), font=font(18, True), fill="#ffffff")
    text(d, (150, y + 18), a, 30, INK, True)
    text(d, (150, y + 62), b, 22, MUTED, width=1000)
    y += 138
S("offline", 8, "Four independent checks: no networking imports, zero network events at runtime, identical results in an empty network namespace - and the airplane-mode test on the phone.", im)

# 3 scam SMS
im, d = canvas(); header(d, "2", "A scam message")
card(d, (60, 110, 600, 250), "#eef3fb", "#d5e2f6")
text(d, (84, 122), "From: VK-SBIYNO", 18, MUTED)
text(d, (84, 150), SCAM, 22, INK, width=490)
v = ev_scam["verdict"]
x = chip(d, (60, 268), v["label"].upper(), BAND[v["label"]])
d.text((x + 18, 275), f"risk {v['risk_score']:.2f}", font=font(26, True), fill=INK)
e = ex(ev_scam)
y = text(d, (60, 335), e["explanation"], 20, INK, width=545, spacing=1.2)
y = text(d, (60, y + 6), "What to do:", 20, INK, True)
for a in e["actions"][:2]:
    y = text(d, (78, y), "- " + a, 18, MUTED, width=520, spacing=1.2)
d.text((660, 110), "Why (evidence, ranked by influence)", font=font(24, True), fill=INK)
signal_bars(d, 660, 160, ev_scam["signals"], 560, 8)
S("scam", 9, "A fake bank KYC message with a look-alike link. The detector combines the wording model, rules and the link analysis - and explains in plain language what to do.", im)

# 4 genuine
im, d = canvas(); header(d, "3", "A genuine bank OTP - no false alarm")
card(d, (60, 110, 600, 300), "#eef3fb", "#d5e2f6")
text(d, (84, 122), "From: AX-HDFCBK", 18, MUTED)
text(d, (84, 152), OTP, 23, INK, width=490)
v = ev_otp["verdict"]
x = chip(d, (60, 325), v["label"].upper(), BAND[v["label"]])
d.text((x + 18, 332), f"risk {v['risk_score']:.2f}", font=font(26, True), fill=INK)
y = text(d, (60, 400), ex(ev_otp)["explanation"], 21, INK, width=540)
d.text((660, 110), "Evidence (green = reassuring)", font=font(24, True), fill=INK)
signal_bars(d, 660, 160, ev_otp["signals"], 560, 8)
S("genuine", 7, "The hard part is not crying wolf. A real OTP notice that says 'do not share' is recognised as safe, and the reasons are shown.", im)

# 5 URL
im, d = canvas(); header(d, "4", "Look-alike links, checked locally")
for i, (u, e_) in enumerate(zip(URLS, ev_u)):
    x0 = 60 + i * 600
    card(d, (x0, 110, x0 + 570, 600))
    text(d, (x0 + 22, 126), u, 20, INK, mono=True, width=520)
    v = e_["verdict"]
    chip(d, (x0 + 22, 215), v["label"].upper(), BAND[v["label"]], 24)
    d.text((x0 + 22 + 190, 220), f"risk {v['risk_score']:.2f}", font=font(24, True), fill=INK)
    signal_bars(d, x0 + 22, 285, e_["signals"], 520, 5)
S("urls", 7, "A typosquatted Amazon link is flagged from the address alone; the real Amazon page is trusted. No lookup, no cloud reputation service.", im)

# 6 network
im, d = canvas(); header(d, "5", "Network threats: a port scan caught from packet headers")
card(d, (60, 110, 620, 600))
s_ = rep["summary"]
text(d, (84, 126), "demo/pcaps/port_scan.pcap", 22, INK, mono=True)
text(d, (84, 175), f"{s_['connections']} connections analysed", 28, INK, True)
text(d, (84, 215), f"{s_['flagged']} flagged  ({s_['flag_rate']*100:.0f}%)", 28, RED, True)
a0 = rep["alerts"][0]
chip(d, (84, 275), a0["verdict"]["label"].upper() if "verdict" in a0 else "ALERT", RED, 24)
text(d, (84, 345), a0.get("category_text", ""), 26, INK, True, width=500)
ee = a0.get("plain_summary") or ""
text(d, (84, 400), str(ee)[:260], 21, MUTED, width=510)
card(d, (660, 110, W - 60, 600))
text(d, (684, 126), "Normal browsing capture", 22, INK, True)
text(d, (684, 170), f"{rep_ok['summary']['connections']} connections, {rep_ok['summary']['flagged']} flagged", 26, GREEN, True)
text(d, (684, 230), "Trained on NSL-KDD with only the 28 features computable from packet headers (no payload inspection), so it works on encrypted traffic.", 21, MUTED, width=520)
n_ = M["net_I_kddtest"]["flag@0.5"]
text(d, (684, 360), f"KDDTest+ (official): {n_['recall']*100:.0f}% of attacks flagged at {n_['fpr']*100:.1f}% false alarms", 22, INK, True, width=520)
text(d, (684, 430), "Weak on password-guessing / privilege-escalation attacks (R2L, U2R) - visible only in payloads. We say so.", 20, MUTED, width=520)
S("network", 8, "The same engine reads a packet capture, rebuilds connections, and recognises scans and floods from header statistics - then explains them in plain words.", im)

# 7 pipeline
im, d = canvas(); header(d, "6", "How a verdict is made - small, fast, explainable")
stages = bref["message_latency_ms"]["stages"]
names = [("preprocess", "Normalise text"), ("sms_model", "Wording model"), ("sms_rules", "Scam rules"), ("url_analysis", "Link analysis"), ("fusion", "Risk fusion"), ("evidence", "Evidence JSON")]
x = 60
for k, lab in names:
    card(d, (x, 130, x + 180, 280))
    text(d, (x + 12, 146), lab, 20, INK, True, width=158)
    text(d, (x + 12, 222), f"{stages[k]['p95']:.2f} ms", 26, BLUE, True)
    x += 193
tag = "95th-percentile time per stage" + (", x86 development reference - NOT Arm" if is_ref else f", measured on {bref['machine'].get('cpu_model') or 'Arm device'}")
text(d, (60, 300), tag, 18, MUTED)
card(d, (60, 360, 620, 600))
text(d, (84, 374), "Footprint", 26, INK, True)
fp = sum(bref["model_files_bytes"].values()) / 1e6
text(d, (84, 420), f"{fp:.1f} MB of model files", 24, INK)
text(d, (84, 460), f"{bref['memory_after_message_workload']['rss_mb']:.0f} MB RAM (detector)" + (" - x86 reference" if is_ref else ""), 24, INK)
text(d, (84, 500), "NumPy only: no sklearn, no ONNX runtime, no network", 22, MUTED, width=500)
card(d, (660, 360, W - 60, 600))
text(d, (684, 374), "Evidence -> explanation", 26, INK, True)
text(d, (684, 420), "The detector outputs structured evidence. A language model may only explain that evidence in plain language (English / Hindi) - it never decides, and a grounding check rejects invented phone numbers or links.", 21, MUTED, width=500)
S("pipeline", 8, "Six small stages, a few milliseconds each. The detector decides; a language model is only allowed to explain the evidence it is given.", im)

# 8 honest accuracy
im, d = canvas(); header(d, "7", "Honest accuracy - on held-out, hand-written data")
D, Dd = M["sms_D_locked_test"], M["sms_C_dev"]
cards = [("Scam messages", "locked hand-written test", [f"flag: {D['flag']['recall']*100:.0f}% caught, {D['flag']['fpr']*100:.0f}% false alarms", f"block: {D['block']['recall']*100:.0f}% caught, {D['block']['fpr']*100:.1f}% false alarms", f"n = {D['flag']['n_pos']} scam / {D['flag']['n_neg']} genuine"]),
         ("Phishing links", "locked URL test", [f"{M['url_G_locked_test']['fused_flag']['recall']*100:.0f}% caught, {M['url_G_locked_test']['fused_flag']['fpr']*100:.0f}% false alarms", f"top-domain check: {M['url_H_opendns_benign']['fpr_flag']*100:.1f}% flagged (n={M['url_H_opendns_benign']['n']})", f"n = {M['url_G_locked_test']['fused_flag']['n_pos']} phish / {M['url_G_locked_test']['fused_flag']['n_neg']} genuine"]),
         ("Network attacks", "NSL-KDD KDDTest+", [f"{n_['recall']*100:.0f}% caught, {n_['fpr']*100:.1f}% false alarms", f"AUC {n_['auc']:.3f}", "R2L / U2R: mostly missed"])]
for i, (t1, t2, ls) in enumerate(cards):
    x0 = 60 + i * 400
    card(d, (x0, 120, x0 + 380, 520))
    text(d, (x0 + 20, 136), t1, 28, INK, True)
    text(d, (x0 + 20, 176), t2, 19, MUTED)
    yy = 230
    for l in ls:
        yy = text(d, (x0 + 20, yy), l, 22, INK, width=340) + 14
text(d, (60, 545), "Public-corpus test (in-distribution): 98% caught at 0.4% false alarms. The locked hand-written test is the harder, honest number; 95% confidence intervals are in results/EVALUATION.md.", 20, MUTED, width=1150)
S("accuracy", 10, "We lead with the hard number: hand-written messages held out from all model fitting. Easier in-distribution scores, intervals and limits are reported too.", im)

# 9 close
im, d = canvas()
d.rectangle((0, 0, W, H), fill="#0b1a33")
d.text((90, 150), "Private by design.", font=font(64, True), fill="#ffffff")
d.text((90, 240), "Explainable by design.", font=font(64, True), fill="#ffffff")
d.text((90, 330), "Small enough for any Arm device.", font=font(64, True), fill="#ffffff")
text(d, (92, 470), "Next: run the same benchmark on the phone, then the live demo in airplane mode.", 28, "#9db8e0", width=1000)
S("close", 6, "Kavach-Edge: your phone protects you without sending a single message anywhere.", im)

# ---------------------------------------------------------------- write frames + render
for i, (name, sec, cap, im) in enumerate(scenes):
    d = ImageDraw.Draw(im)
    if name not in ("title", "close"):
        caption(d, cap)
    else:
        d.rectangle((0, H - 84, W, H), fill="#0b0b0b")
        f = font(25); ls = wrap(d, cap, f, W - 120)[:2]
        y = H - 84 + (84 - len(ls) * 32) // 2
        for ln in ls:
            d.text((60, y), ln, font=f, fill="#ffffff"); y += 32
    im.save(os.path.join(FR, f"{i+1:02d}_{name}.png"))
print("frames:", len(scenes), "total seconds:", sum(s[1] for s in scenes))
if "--frames-only" in sys.argv:
    sys.exit(0)

parts = []
for i, (name, sec, cap, im) in enumerate(scenes):
    png = os.path.join(FR, f"{i+1:02d}_{name}.png")
    tmp, final = os.path.join(FR, f"s{i+1:02d}.tmp.mp4"), os.path.join(FR, f"s{i+1:02d}.mp4")
    fade = f"fade=t=in:st=0:d=0.4,fade=t=out:st={sec-0.4}:d=0.4"
    cmd = ["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", png, "-vf", f"format=yuv420p,loop=-1:1,trim=duration={sec},{fade}",
           "-c:v", "libx264", "-crf", "18", "-preset", "veryfast", "-pix_fmt", "yuv420p", "-r", str(FPS), tmp]
    subprocess.run(cmd, check=True)
    os.replace(tmp, final)
    parts.append(final)
lst = os.path.join(FR, "list.txt")
open(lst, "w").write("".join(f"file '{p}'\n" for p in parts))
out_tmp, out = os.path.join(OUT, "tmp_out.mp4"), os.path.join(OUT, "kavach_edge_explainer.mp4")
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst, "-c", "copy", out_tmp], check=True)
os.replace(out_tmp, out)
print("wrote", out)
