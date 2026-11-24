#!/usr/bin/env python3
"""Write the Kavach app's cold-start samples into phone bench JSONs.

run_bench.py measures cold start by spawning a fresh Python process; inside the Android app (Chaquopy)
there is no Python executable to spawn, so the app measures it itself after `am force-stop`:
Python start -> import + Detector() -> first verdict (same message as run_bench.cold_start).

    python3 bench/coldstart_from_app.py --samples results/bench/coldstart_phone_arm64.jsonl results/bench/bench_phone_arm64_run*.json
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "bench"))
from run_bench import summ  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True, help="coldstart.jsonl pulled from the phone")
    ap.add_argument("bench", nargs="+", help="bench JSON files to update")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(a.samples, encoding="utf-8") if l.strip()]
    block = {"load_ms": summ([r["load_ms"] for r in rows]), "first_verdict_ms": summ([r["first_verdict_ms"] for r in rows]),
             "python_start_ms": summ([r["python_start_ms"] for r in rows]),
             "source": "Kavach Android app after am force-stop (Chaquopy); load_ms = import + Detector(); "
                       "python_start_ms (Python.start) is extra and reported separately"}
    for f in a.bench:
        res = json.load(open(f, encoding="utf-8"))
        res["cold_start"] = block
        json.dump(res, open(f, "w", encoding="utf-8"), indent=1)
    print(f"cold start n={len(rows)}: load p50 {block['load_ms']['p50']} ms, first verdict p50 "
          f"{block['first_verdict_ms']['p50']} ms, python start p50 {block['python_start_ms']['p50']} ms")


if __name__ == "__main__":
    main()
