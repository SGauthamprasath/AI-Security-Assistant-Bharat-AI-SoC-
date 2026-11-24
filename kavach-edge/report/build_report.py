#!/usr/bin/env python3
"""Assemble report/TECHNICAL_REPORT.md from hand-written sections + auto-generated, measured sections.   python3 report/build_report.py

Static sections (report/sections/0[0-2]_*.md, 07_*.md) use {{placeholders}} filled from results/metrics.json so prose can never drift from the numbers.
Auto sections: results/EVALUATION.md (03), results/OFFLINE_PROOF.md (04b), report/sections/05_hardware_performance.md (bench/make_report.py),
results/STUDY_RESULTS.md (06, or a PENDING block when the study has not been run).
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(ROOT, "report")
M = json.load(open(os.path.join(ROOT, "results", "metrics.json")))


def pct(x, nd=0):
    return f"{x*100:.{nd}f}%"


D, C, A, B = M["sms_D_locked_test"], M["sms_C_dev"], M["sms_A_public_test"], M["sms_B_composite_test"]
G, E, H = M["url_G_locked_test"], M["url_E_test_hosts"], M["url_H_opendns_benign"]
N = M["net_I_kddtest"]
ab = M["sms_ablation_locked_test"]
vals = {
    "A_recall": pct(A["flag"]["recall"], 1), "A_fpr": pct(A["flag"]["fpr"], 1), "A_n": str(A["flag"]["n"]), "A_auc": f"{A['flag']['auc']:.3f}",
    "A_prec1": pct(A["flag"]["precision_at_1pct_prevalence"], 0),
    "B_recall": pct(B["flag"]["recall"], 1), "B_fpr": pct(B["flag"]["fpr"], 1),
    "C_recall": pct(C["flag"]["recall"], 0), "C_fpr": pct(C["flag"]["fpr"], 0),
    "D_recall": pct(D["flag"]["recall"], 0), "D_fpr": pct(D["flag"]["fpr"], 1), "D_auc": f"{D['flag']['auc']:.3f}",
    "D_block_recall": pct(D["block"]["recall"], 0), "D_block_fpr": pct(D["block"]["fpr"], 1),
    "D_npos": str(D["flag"]["n_pos"]), "D_nneg": str(D["flag"]["n_neg"]), "D_prec1": pct(D["flag"]["precision_at_1pct_prevalence"], 0),
    "D_block_prec1": pct(D["block"]["precision_at_1pct_prevalence"], 0),
    "abl_text": pct(ab["text model only"]["recall"], 0), "abl_text_auc": f"{ab['text model only']['auc']:.3f}", "abl_full_auc": f"{ab['FULL fusion']['auc']:.3f}",
    "url_E_auc": f"{E['host_model_only_auc']:.3f}", "url_E_recall": pct(E["fused_flag"]["recall"], 0), "url_E_fpr": pct(E["fused_flag"]["fpr"], 1),
    "url_G_recall": pct(G["fused_flag"]["recall"], 0), "url_G_fpr": pct(G["fused_flag"]["fpr"], 0), "url_H_fpr": pct(H["fpr_flag"], 2), "url_H_n": str(H["n"]),
    "net_recall": pct(N["flag@0.5"]["recall"], 0), "net_fpr": pct(N["flag@0.5"]["fpr"], 1), "net_auc": f"{N['flag@0.5']['auc']:.3f}", "net_prec": pct(N["flag@0.5"]["precision"], 1),
    "net_dos": pct(N["recall_by_class"]["dos"], 0), "net_probe": pct(N["recall_by_class"]["probe"], 0), "net_r2l": pct(N["recall_by_class"]["r2l"], 0), "net_u2r": pct(N["recall_by_class"]["u2r"], 0),
}
bf = os.path.join(ROOT, "results", "bench", "bench_sandbox_x86.json")
if os.path.exists(bf):
    b = json.load(open(bf))
    vals.update({"model_mb": f"{sum(b['model_files_bytes'].values())/1e6:.1f}", "x86_p50": f"{b['message_latency_ms']['total']['p50']:.2f}", "x86_p95": f"{b['message_latency_ms']['total']['p95']:.2f}",
                 "x86_rss": f"{b['memory_after_message_workload']['rss_mb']:.0f}"})

# Phone (Arm) numbers: median over the bench_phone_arm64_run*.json files. Missing -> PENDING, never a guess.
import glob as _glob  # noqa: E402
import statistics as _st  # noqa: E402
_P = "**PENDING**"
_runs = [json.load(open(f)) for f in sorted(_glob.glob(os.path.join(ROOT, "results", "bench", "bench_phone_arm64_run*.json")))]


def _med(*path, nd=0):
    v = []
    for r in _runs:
        for k in path:
            r = r.get(k) if isinstance(r, dict) else None
        if isinstance(r, (int, float)):
            v.append(r)
    return f"{_st.median(v):.{nd}f}" if v else _P


vals.update({
    "arm_runs": str(len(_runs)) if _runs else _P,
    "arm_p50": _med("message_latency_ms", "total", "p50", nd=2), "arm_p95": _med("message_latency_ms", "total", "p95", nd=2),
    "arm_rss": _med("memory_after_message_workload", "rss_mb"), "arm_pss": _med("memory_after_message_workload", "pss_mb"),
    "arm_cold": _med("cold_start", "load_ms", "p50"), "arm_pystart": _med("cold_start", "python_start_ms", "p50"),
    "llm_ttft": _med("advisor", "ttfb_ms", "p50"), "llm_total": _med("advisor", "total_ms", "p50"),
    "llm_tps": _med("advisor", "tokens_per_s", "p50", nd=1), "llm_rss": _med("memory_after_advisor", "rss_mb"),
    "llm_shown": _med("advisor", "shown_from_llama"), "llm_samples": _med("advisor", "samples"),
})
_inj = os.path.join(ROOT, "results", "injection.json")
if os.path.exists(_inj):
    J = json.load(open(_inj, encoding="utf-8"))
    ph = J.get("phone", {})
    vals.update({"inj_n": str(J["n"]), "inj_lowered": str(len(J["verdict_lowered"])), "inj_raised": str(len(J["verdict_raised"])),
                 "inj_leaks": str(len(J["attack_text_in_prompt"])), "inj_phone_equal": str(ph.get("verdict_equal_phone_laptop", _P)),
                 "inj_llama": str(ph.get("shown_llama", _P)), "inj_template": str(ph.get("shown_template", _P))})


def fill(t):
    return re.sub(r"\{\{(\w+)\}\}", lambda m: vals.get(m.group(1), "**MISSING:" + m.group(1) + "**"), t)


def rd(p):
    return open(p, encoding="utf-8").read()


parts = []
for f in ("00_summary.md", "01_problem_approach.md", "02_data_methodology.md"):
    parts.append(fill(rd(os.path.join(R, "sections", f))))
parts.append("# 3. Evaluation\n\n" + rd(os.path.join(ROOT, "results", "EVALUATION.md")).split("\n", 2)[2].replace("## ", "### ") +
             "\n![ROC curves](figs/roc_curves.png)\n\n![Ablation](figs/sms_ablation.png)\n\n![Network confusion](figs/net_confusion.png)\n")
parts.append(fill(rd(os.path.join(R, "sections", "04_advisor_privacy.md"))))
parts.append(rd(os.path.join(ROOT, "results", "OFFLINE_PROOF.md")).replace("# Offline", "### Offline", 1) + "\n")
parts.append(rd(os.path.join(R, "sections", "05_hardware_performance.md")))
sp = os.path.join(ROOT, "results", "STUDY_RESULTS.md")
parts.append("# 6. User study\n\n" + (rd(sp).split("\n", 1)[1] if os.path.exists(sp) else
             "**PENDING** - the study has not been run yet. Kit: `study/` (protocol, offline app, analysis). After collecting 8-15 participants run `python3 study/analyze_study.py --report` and rebuild this report.\n"))
parts.append(fill(rd(os.path.join(R, "sections", "07_limitations_roadmap.md"))))
out = "\n\n".join(parts)
os.makedirs(os.path.join(R, "figs"), exist_ok=True)
for f in os.listdir(os.path.join(ROOT, "results", "figs")):
    open(os.path.join(R, "figs", f), "wb").write(open(os.path.join(ROOT, "results", "figs", f), "rb").read())
open(os.path.join(R, "TECHNICAL_REPORT.md"), "w", encoding="utf-8").write(out)
pend = out.count("PENDING")
print(f"wrote report/TECHNICAL_REPORT.md  ({len(out.split())} words, {pend} PENDING markers - each is a measurement still owed)")
