#!/usr/bin/env python3
"""Fill the `advisor` block of a phone bench JSON from the Kavach app's own Llama measurements.

run_bench.py's --advisor-cmd needs a separate Llama process, which the Android app does not have: the app
runs Llama in-process with ExecuTorch's LlmModule and logs every run to llm_runs.jsonl (time to first
token, prompt/decode speed, peak RSS, from ExecuTorch's own stats). This script summarises those runs
with run_bench's summ() and writes them into a bench JSON, marked with their source.

    python3 bench/llm_from_app.py --runs results/bench/llm_runs_phone_arm64_run1.jsonl --bench results/bench/bench_phone_arm64_run1.json

Only runs whose id starts with --prefix (default "adv", the advisor benchmark set) are used.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bench"))
from run_bench import summ  # noqa: E402  (same percentile code as every other number in the report)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True, help="llm_runs.jsonl pulled from the phone")
    ap.add_argument("--bench", required=True, help="bench JSON file to update")
    ap.add_argument("--prefix", default="adv", help="only use runs whose id starts with this")
    a = ap.parse_args()

    runs = [json.loads(l) for l in open(a.runs, encoding="utf-8") if l.strip()]
    runs = [r for r in runs if str(r.get("id", "")).startswith(a.prefix)]
    if not runs:
        sys.exit("no matching runs")
    total = [r["et_stats"]["inference_end_ms"] - r["et_stats"]["inference_start_ms"] for r in runs]
    block = {
        "measured": True,
        "source": "Kavach Android app: ExecuTorch LlmModule in-process (executorch-android 1.1.0, XNNPACK CPU); "
                  "stats from ExecuTorch's onStats callback; not run_bench --advisor-cmd",
        "model": runs[0].get("model"), "samples": len(runs),
        "ttfb_ms": summ([r["ttft_ms"] for r in runs]),
        "total_ms": summ(total),
        "tokens_per_s": summ([r["decode_tok_s"] for r in runs]),
        "prefill_tokens_per_s": summ([r["prefill_tok_s"] for r in runs]),
        "prompt_tokens": summ([r["prompt_tokens"] for r in runs]),
        "generated_tokens": summ([r["generated_tokens"] for r in runs]),
        "model_load_ms": runs[0].get("load_ms"),
        "shown_from_llama": sum(r["source"] == "llama" for r in runs),
    }
    out = a.bench
    res = json.load(open(out, encoding="utf-8"))
    res["advisor"] = block
    res["memory_after_advisor"] = {"rss_mb": max(r["peak_rss_mb"] for r in runs), "pss_mb": None,
                                   "note": "peak RSS (VmHWM) of the app process incl. detector, Python and Llama"}
    json.dump(res, open(out, "w", encoding="utf-8"), indent=1)
    print(f"{out}: advisor ttft p50 {block['ttfb_ms']['p50']} ms, decode p50 {block['tokens_per_s']['p50']} tok/s, "
          f"n={len(runs)}")


if __name__ == "__main__":
    main()
