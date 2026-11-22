#!/usr/bin/env python3
"""Device telemetry sampler (Linux / Android-via-Termux / Raspberry Pi). Stdlib only.

Why it exists: PS3 asks for measured latency, memory, battery and temperature. Latency and memory can be measured in-process
(see run_bench.py); battery and temperature must come from the OS. This module reads whatever the device exposes and records
`None` for anything it does not - it never invents a value.

Usage as a library:   s = Sampler(interval=1.0); s.start(); ...workload...; s.stop(); s.summary()
Usage as a CLI:       python3 bench/sysmon.py --seconds 600 --interval 2 --out results/bench/telemetry_idle.csv
Sources tried (first that works wins):
  temperature  /sys/class/thermal/thermal_zone*/temp (milli-degC), `vcgencmd measure_temp` (Raspberry Pi)
  battery      /sys/class/power_supply/*/{capacity,status,temp,voltage_now,current_now}, `termux-battery-status` (Termux:API)
  cpu freq     /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq
  throttling   `vcgencmd get_throttled` (Pi)
"""
import argparse
import csv
import glob
import json
import os
import shutil
import subprocess
import threading
import time


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def _run(cmd, timeout=3):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return None


def thermal_zones():
    out = {}
    for z in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
        t, typ = _read(z + "/temp"), _read(z + "/type")
        if t and t.lstrip("-").isdigit():
            v = int(t)
            out[typ or os.path.basename(z)] = v / 1000.0 if abs(v) > 1000 else float(v)
    return out


def battery_sysfs():
    for ps in sorted(glob.glob("/sys/class/power_supply/*")):
        if _read(ps + "/type") == "Battery":
            d = {"capacity_pct": _read(ps + "/capacity"), "status": _read(ps + "/status")}
            for k, f, scale in (("temp_c", "temp", 10.0), ("voltage_v", "voltage_now", 1e6), ("current_ma", "current_now", 1e3)):
                v = _read(f"{ps}/{f}")
                d[k] = (float(v) / scale) if v and v.lstrip("-").isdigit() else None
            d["capacity_pct"] = float(d["capacity_pct"]) if d["capacity_pct"] else None
            return d
    return None


def battery_termux():
    if not shutil.which("termux-battery-status"):
        return None
    try:
        j = json.loads(_run(["termux-battery-status"], 5) or "{}")
        return {"capacity_pct": j.get("percentage"), "status": j.get("status"), "temp_c": j.get("temperature"), "current_ma": (j.get("current") or 0) / 1000.0 if j.get("current") is not None else None, "voltage_v": None}
    except Exception:
        return None


def pi_vcgencmd():
    if not shutil.which("vcgencmd"):
        return {}
    d = {}
    t = _run(["vcgencmd", "measure_temp"])
    if t and "=" in t:
        try:
            d["soc_temp_c"] = float(t.split("=")[1].replace("'C", ""))
        except ValueError:
            pass
    th = _run(["vcgencmd", "get_throttled"])
    if th and "=" in th:
        d["throttled_flags"] = th.split("=")[1]
    return d


def cpu_freq_mhz():
    f = [int(x) for x in (_read(p) or "0" for p in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")) if x.isdigit()]
    return (sum(f) / len(f) / 1000.0, max(f) / 1000.0) if f else (None, None)


def mem_available_mb():
    for line in (_read("/proc/meminfo") or "").splitlines():
        if line.startswith("MemAvailable"):
            return int(line.split()[1]) / 1024.0
    return None


def sample():
    z = thermal_zones()
    b = battery_sysfs() or battery_termux() or {}
    pi = pi_vcgencmd()
    avg, mx = cpu_freq_mhz()
    temps = list(z.values()) + ([pi["soc_temp_c"]] if "soc_temp_c" in pi else [])
    return {"t": time.time(), "temp_max_c": max(temps) if temps else None, "temp_zones": z, "batt_pct": b.get("capacity_pct"), "batt_status": b.get("status"),
            "batt_temp_c": b.get("temp_c"), "batt_current_ma": b.get("current_ma"), "batt_voltage_v": b.get("voltage_v"),
            "cpu_mhz_avg": avg, "cpu_mhz_max": mx, "mem_avail_mb": mem_available_mb(), "load1": float((_read("/proc/loadavg") or "nan nan").split()[0]),
            "throttled_flags": pi.get("throttled_flags")}


class Sampler:
    def __init__(self, interval=1.0):
        self.interval, self.rows, self._stop, self._th = interval, [], threading.Event(), None

    def start(self):
        self.rows.append(sample())
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.rows.append(sample())

    def stop(self):
        self._stop.set()
        if self._th:
            self._th.join(timeout=5)
        self.rows.append(sample())

    def summary(self):
        def col(k):
            return [r[k] for r in self.rows if r.get(k) is not None]
        t, b, c = col("temp_max_c"), col("batt_pct"), col("batt_current_ma")
        dur = self.rows[-1]["t"] - self.rows[0]["t"] if len(self.rows) > 1 else 0.0
        out = {"samples": len(self.rows), "duration_s": round(dur, 1), "temperature_available": bool(t), "battery_available": bool(b)}
        if t:
            out.update({"temp_start_c": t[0], "temp_end_c": t[-1], "temp_max_c": max(t), "temp_rise_c": round(t[-1] - t[0], 2)})
        if b:
            out.update({"battery_start_pct": b[0], "battery_end_pct": b[-1], "battery_drop_pct": round(b[0] - b[-1], 2),
                        "battery_drain_pct_per_hour": round((b[0] - b[-1]) / (dur / 3600.0), 2) if dur >= 60 else None})
        if c:
            out["battery_current_ma_mean"] = round(sum(c) / len(c), 1)
        cm = col("cpu_mhz_avg")
        if cm:
            out["cpu_mhz_mean"], out["cpu_mhz_min"] = round(sum(cm) / len(cm), 0), round(min(cm), 0)
        fl = [r["throttled_flags"] for r in self.rows if r.get("throttled_flags")]
        if fl:
            out["pi_throttled_flags_last"] = fl[-1]
        return out

    def to_csv(self, path):
        if not self.rows:
            return
        keys = [k for k in self.rows[0] if k != "temp_zones"]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(self.rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--out", default="results/bench/telemetry.csv")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    s = Sampler(a.interval)
    s.start()
    time.sleep(a.seconds)
    s.stop()
    s.to_csv(a.out)
    print(json.dumps(s.summary(), indent=1))
