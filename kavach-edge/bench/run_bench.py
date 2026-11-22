#!/usr/bin/env python3
"""Kavach-Edge benchmark harness  (run THE SAME command on every device; protocol in bench/BENCHMARK_PROTOCOL.md).

    python3 bench/run_bench.py --label pixel8_arm64 --device-note "Pixel 8, Termux, Android 15, no charger" --iters 2000 --sustained-seconds 600

What it measures (all in-process, wall-clock, time.perf_counter_ns):
  * cold start        fresh Python process -> models loaded -> first verdict          (subprocess, 5 repeats)
  * stage latency     preprocess / sms_model / sms_rules / url_analysis / fusion / evidence, p50/p90/p95/p99, per message
  * end-to-end        analyze_message total, analyze_url total, and a pcap (connections/s)
  * memory            RSS and PSS (proportional set size, the honest number on Android/Linux) before load, after load, after workload
  * model footprint   bytes on disk for every model file
  * sustained run     loop for N seconds while telemetry (temperature, battery, cpu frequency) is sampled by sysmon.py;
                      reports latency drift between first and last minute (thermal throttling shows up here)
  * advisor hook      OPTIONAL: --advisor-cmd runs an external command (e.g. your ExecuTorch Llama runner) once per HIGH-RISK
                      message with the grounded prompt on stdin; we record wall time, time-to-first-byte and tokens/s if the
                      command prints a final JSON line {"tokens": N}. Without it, advisor timing is reported as NOT MEASURED.

The result JSON records `machine`, `is_arm` and `label`. Numbers measured on x86 are tagged `reference_only` so no report can
mistake them for Arm results.
"""
import argparse
import gc
import json
import os
import platform
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "bench"))
import sysmon  # noqa: E402


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * q
    f, c = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def summ(xs):
    return {"n": len(xs), "mean": round(statistics.fmean(xs), 4), "p50": round(pct(xs, .5), 4), "p90": round(pct(xs, .9), 4),
            "p95": round(pct(xs, .95), 4), "p99": round(pct(xs, .99), 4), "max": round(max(xs), 4)} if xs else {"n": 0}


def mem_mb():
    """(rss, pss) in MB from /proc/self - works on Linux, Android (Termux/adb shell) and Raspberry Pi OS."""
    rss = pss = None
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmRSS"):
                rss = int(line.split()[1]) / 1024.0
    except OSError:
        pass
    try:
        for line in open("/proc/self/smaps_rollup"):
            if line.startswith("Pss:"):
                pss = int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return {"rss_mb": round(rss, 1) if rss else None, "pss_mb": round(pss, 1) if pss else None}


def machine_info():
    cpu = None
    try:
        for line in open("/proc/cpuinfo"):
            if line.lower().startswith(("model name", "hardware", "cpu part", "model\t")):
                cpu = line.split(":", 1)[1].strip()
                if line.lower().startswith("model name") or line.lower().startswith("hardware"):
                    break
    except OSError:
        pass
    m = platform.machine().lower()
    return {"machine": platform.machine(), "is_arm": m.startswith(("aarch64", "arm")), "system": platform.system(), "release": platform.release(),
            "python": platform.python_version(), "cpu_model": cpu, "logical_cpus": os.cpu_count(),
            "cpu_freq_mhz_max": sysmon.cpu_freq_mhz()[1]}


def cold_start(repeats=5):
    """Fresh interpreter each time: import + load all models + first verdict. This is what a user feels after a reboot."""
    code = ("import time,sys;t=time.perf_counter();sys.path.insert(0,%r);"
            "from kavach.pipeline import Detector;d=Detector();t1=time.perf_counter();"
            "d.analyze_message('Your SBI account is blocked. Update KYC at http://sbi-kyc.xyz now',None,with_prompt=False);t2=time.perf_counter();"
            "print(round((t1-t)*1000,1),round((t2-t1)*1000,2))" % ROOT)
    load, first = [], []
    for _ in range(repeats):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT).stdout.split()
        if len(out) == 2:
            load.append(float(out[0]))
            first.append(float(out[1]))
    return {"load_ms": summ(load), "first_verdict_ms": summ(first)}


def corpus():
    msgs = []
    for f in ("kavachbench_in.jsonl", "kavachbench_in_test.jsonl"):
        msgs += [json.loads(l) for l in open(os.path.join(ROOT, "data", f))]
    urls = []
    for f in ("kavachbench_urls.jsonl", "kavachbench_urls_test.jsonl"):
        urls += [json.loads(l)["url"] for l in open(os.path.join(ROOT, "data", f))]
    return msgs, urls


def run_advisor(cmd, prompt):
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    p.stdin.write(json.dumps(prompt))
    p.stdin.close()
    first = p.stdout.read(1)
    ttfb = (time.perf_counter() - t0) * 1000
    rest = p.stdout.read()
    total = (time.perf_counter() - t0) * 1000
    tokens = None
    for line in reversed((first + rest).strip().splitlines()):
        try:
            tokens = json.loads(line).get("tokens")
            break
        except Exception:
            continue
    return {"ttfb_ms": ttfb, "total_ms": total, "tokens": tokens, "tok_per_s": (tokens / ((total - ttfb) / 1000)) if tokens and total > ttfb else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="short device tag, e.g. pixel8_arm64, rpi5_arm64, sandbox_x86")
    ap.add_argument("--device-note", default="", help="free text: model, OS, charger state, screen state, battery %% at start")
    ap.add_argument("--iters", type=int, default=2000)
    ap.add_argument("--warmup", type=int, default=200)
    ap.add_argument("--sustained-seconds", type=int, default=0, help="run a continuous loop this long with telemetry (use 600-1800 on the phone)")
    ap.add_argument("--advisor-cmd", default=None, help="shell command for the on-device LLM runner; prompt JSON on stdin")
    ap.add_argument("--advisor-samples", type=int, default=10)
    ap.add_argument("--skip-cold", action="store_true")
    a = ap.parse_args()

    res = {"label": a.label, "device_note": a.device_note, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "machine": machine_info()}
    res["reference_only"] = not res["machine"]["is_arm"]
    if res["reference_only"]:
        print("!! NOT an Arm machine: results are tagged reference_only and must not be reported as Arm measurements.")
    res["memory_before_load"] = mem_mb()
    if not a.skip_cold:
        print("cold start x5 ...")
        res["cold_start"] = cold_start()

    from kavach.pipeline import Detector
    t = time.perf_counter()
    det = Detector()
    res["in_process_load_ms"] = round((time.perf_counter() - t) * 1000, 1)
    res["memory_after_load"] = mem_mb()
    res["model_footprint_bytes"] = det.model_footprint()
    res["model_files_bytes"] = {f: os.path.getsize(os.path.join(ROOT, "models", f)) for f in sorted(os.listdir(os.path.join(ROOT, "models")))}
    msgs, urls = corpus()

    # ---- warm-up (JIT-less, but fills caches / page-faults model pages in)
    for i in range(a.warmup):
        det.analyze_message(msgs[i % len(msgs)]["text"], msgs[i % len(msgs)]["sender"], with_prompt=False)

    # ---- message latency
    stages, totals, tot_prompt = {}, [], []
    gc.collect(); gc.disable()
    for i in range(a.iters):
        m = msgs[i % len(msgs)]
        ev = det.analyze_message(m["text"], m["sender"], with_prompt=False)
        totals.append(ev["performance"]["total_ms"])
        for k, v in ev["performance"]["stage_ms"].items():
            stages.setdefault(k, []).append(v)
        if i % 50 == 0:
            gc.collect()
    gc.enable()
    res["message_latency_ms"] = {"total": summ(totals), "stages": {k: summ(v) for k, v in stages.items()}}
    # with grounded-advisor prompt construction
    for i in range(min(500, a.iters)):
        m = msgs[i % len(msgs)]
        ev = det.analyze_message(m["text"], m["sender"], with_prompt=True)
        tot_prompt.append(ev["performance"]["total_ms"])
    res["message_latency_with_prompt_ms"] = summ(tot_prompt)
    ul = []
    for i in range(a.iters):
        ul.append(det.analyze_url(urls[i % len(urls)], with_prompt=False)["performance"]["total_ms"])
    res["url_latency_ms"] = summ(ul)
    res["throughput_msgs_per_s"] = round(1000.0 / statistics.fmean(totals), 1)
    res["memory_after_message_workload"] = mem_mb()   # detector only: before the (scapy-heavy) pcap step below

    # ---- pcap (network monitor)
    pc = {}
    for name in ("normal_browsing", "port_scan", "syn_flood", "mixed_home_network"):
        path = os.path.join(ROOT, "demo", "pcaps", name + ".pcap")
        if not os.path.exists(path):
            continue
        ts = []
        for _ in range(5):
            t0 = time.perf_counter()
            r = det.analyze_pcap(path, with_prompt=False)
            ts.append((time.perf_counter() - t0) * 1000)
        pc[name] = {"connections": r["summary"]["connections"], "ms_p50": round(pct(ts, .5), 1), "connections_per_s": round(r["summary"]["connections"] / (pct(ts, .5) / 1000), 0)}
    res["pcap_analysis"] = pc
    res["memory_after_workload"] = mem_mb()          # includes scapy import for pcap parsing

    # ---- optional on-device LLM advisor
    if a.advisor_cmd:
        ads = []
        high = [m for m in msgs if m["label"] == 1][: a.advisor_samples]
        for m in high:
            ev = det.analyze_message(m["text"], m["sender"], with_prompt=True)
            ads.append(run_advisor(a.advisor_cmd, ev["advisor_prompt"]))
        res["advisor"] = {"measured": True, "cmd": a.advisor_cmd, "ttfb_ms": summ([x["ttfb_ms"] for x in ads]), "total_ms": summ([x["total_ms"] for x in ads]),
                          "tokens_per_s": summ([x["tok_per_s"] for x in ads if x["tok_per_s"]])}
        res["memory_after_advisor"] = mem_mb()
    else:
        res["advisor"] = {"measured": False, "note": "NOT MEASURED - supply --advisor-cmd with the ExecuTorch Llama runner on the device."}

    # ---- sustained run with telemetry
    if a.sustained_seconds > 0:
        s = sysmon.Sampler(interval=2.0)
        s.start()
        t_end = time.time() + a.sustained_seconds
        per_min, cur, cur_start, n, i = [], [], time.time(), 0, 0
        while time.time() < t_end:
            m = msgs[i % len(msgs)]
            i += 1
            t0 = time.perf_counter()
            det.analyze_message(m["text"], m["sender"], with_prompt=False)
            cur.append((time.perf_counter() - t0) * 1000)
            if time.time() - cur_start >= 60:
                per_min.append({"minute": len(per_min) + 1, "p50_ms": round(pct(cur, .5), 3), "p95_ms": round(pct(cur, .95), 3), "n": len(cur)})
                cur, cur_start = [], time.time()
        s.stop()
        s.to_csv(os.path.join(ROOT, "results", "bench", f"telemetry_{a.label}.csv"))
        sm = s.summary()
        res["sustained"] = {"seconds": a.sustained_seconds, "messages_processed": i, "per_minute_latency": per_min, "telemetry": sm}
        if len(per_min) >= 2:
            res["sustained"]["latency_drift_pct_first_to_last_minute"] = round((per_min[-1]["p50_ms"] / per_min[0]["p50_ms"] - 1) * 100, 1)
        # energy per verdict is only reportable when the device reports battery % over a long enough window
        if sm.get("battery_available") and sm.get("battery_drop_pct", 0) > 0:
            res["sustained"]["battery_pct_per_1000_verdicts"] = round(sm["battery_drop_pct"] / (i / 1000.0), 4)
    else:
        res["sustained"] = {"measured": False, "note": "NOT MEASURED - re-run with --sustained-seconds 600 (and battery unplugged) on the device."}

    out = os.path.join(ROOT, "results", "bench", f"bench_{a.label}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)
    L = res["message_latency_ms"]["total"]
    print(f"\n[{a.label}] machine={res['machine']['machine']} arm={res['machine']['is_arm']}")
    print(f"  load {res['in_process_load_ms']} ms | message p50/p95/p99 = {L['p50']}/{L['p95']}/{L['p99']} ms | url p50 {res['url_latency_ms']['p50']} ms | {res['throughput_msgs_per_s']} msg/s")
    print(f"  RSS after load {res['memory_after_load']['rss_mb']} MB, PSS {res['memory_after_load']['pss_mb']} MB | model bytes {sum(res['model_files_bytes'].values())/1e6:.2f} MB")
    print(f"  wrote {out}")


if __name__ == "__main__":
    main()
