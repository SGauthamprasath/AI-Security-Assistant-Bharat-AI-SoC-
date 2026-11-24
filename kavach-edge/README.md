# Kavach-Edge

On-device scam, phishing and network-threat guard for Arm CPUs. *Bharat AI-SoC Challenge 2026-27 - Problem Statement 3.*
NumPy-only runtime, 3.6 MB of models, no network code in the detector, explainable verdicts, grounded LLM-explainer contract.

```bash
pip install -r requirements.txt            # on a phone/Pi you only need numpy (+ pandas only for re-training)
python3 demo/app.py                         # offline UI at http://127.0.0.1:8000
python3 -c "
from kavach.pipeline import Detector
d = Detector()
ev = d.analyze_message('Dear SBI customer your account will be blocked. Update KYC http://sbi-kyc-update.xyz', 'VK-SBIYNO', with_prompt=False)
print(ev['verdict']['label'], ev['verdict']['risk_score'])
print(d.analyze_pcap('demo/pcaps/port_scan.pcap', with_prompt=False)['alerts'][0]['category_text'])"
```

## One command per claim
| Claim | Command | Output |
|---|---|---|
| Accuracy and false alarms (all sets, CIs, ablations, figures) | `python3 scripts/06_evaluate.py` | `results/EVALUATION.md`, `results/metrics.json`, `results/figs/` |
| Works with no network | `python3 offline_proof/verify_offline.py` | `results/OFFLINE_PROOF.md` |
| Latency / memory / size (run ON the device) | `python3 bench/run_bench.py --label phone_arm64 --device-note "..."` | `results/bench/bench_*.json` |
| Battery / temperature | `bench/BENCHMARK_PROTOCOL.md` section 5 (`bench/adb_collect.sh`) | `results/bench/adb_*/summary.json` |
| User study | `study/PROTOCOL.md`; open `study/study_app.html`; `python3 study/analyze_study.py --report` | `results/STUDY_RESULTS.md` |
| Everything in the report | `python3 bench/make_report.py && python3 report/build_report.py` | `report/TECHNICAL_REPORT.md` |
| Tests (parity, schema, offline, pipeline, Android bridge, prompt injection) | `python3 -m pytest -q tests` | 136 tests |

## Layout
```
kavach/        the detector (textnorm, sms_rules, sms_model, urlkit, url_model, netkit, netflow, pcapread, fusion, advisor, pipeline, treeexport) - no networking imports
models/        trained artefacts (float32 .bin weights, flat-array tree .npz, fusion.json) - all that is needed at runtime
scripts/       01 prepare data, 02-04 train, 05 fit fusion + thresholds, 06 evaluate, make_demo_pcaps
data/          KavachBench (hand-written DEV + LOCKED test sets), fetch_data.py, template generator for genuine Indian messages
bench/         benchmark harness, telemetry, adb collection/parsing, report generator, protocol
offline_proof/ four-way offline verification + phone protocol
study/         usability-study kit (offline app, protocol, consent, analysis, self-test)
demo/          offline web UI, synthetic pcaps, explainer video builder + shot list for the phone recording
report/        report sections + builder -> TECHNICAL_REPORT.md
tools/         optional live-capture tool (needs scapy + root; deliberately outside kavach/)
schemas/       kavach.evidence/1.0 JSON schema
```

## Advisor integration (Llama + ExecuTorch) - built, in `../android/`
The Android app runs this package unchanged through Chaquopy. `../android/app/src/main/python/kavach_bridge.py` calls
`Detector.analyze_message`, builds the Llama prompt with `advisor.build_explain_prompt` (detector facts only, never the message
text; 2-3 sentences; stance follows the verdict) in the Llama 3 chat format, and after generation `finalize()` checks the text
(`advisor.check_grounding` plus checks for directing the user to a link/number, contradicting the verdict, certainty claims,
claims of harm already done, and unsupported topics). On any failure it shows `advisor.template_explanation`. Steps always come
from `advisor.REMEDIATION`. Llama 3.2 1B SpinQuant INT4 runs in the app through ExecuTorch's `LlmModule`; its timings are logged
by the app and written into the bench files by `bench/llm_from_app.py`. `advisor.build_prompt` (the wider prompt) is kept unchanged.

## Honest status
Measured: detection accuracy (public + locked hand-written tests), offline proof (laptop: static/runtime/namespace; phone:
`offline_proof/phone_app_check.sh`), x86 reference timings, **phone latency/memory/cold start and Llama timing**
(`results/bench/bench_phone_arm64_run*.json`, taken with airplane mode off - see report section 5), prompt-injection results
(`results/injection.json`), tests (136 in `tests/`).
**Not yet measured: phone battery and temperature over 30 minutes; the user study; the demo video recording.**

Datasets: UCI SMS Spam Collection; IMC'25 user-reported smishing (CC BY 4.0, Agarwal et al.); Phishing.Database; Tranco; OpenDNS top domains; NSL-KDD. See `data/fetch_data.py`.
