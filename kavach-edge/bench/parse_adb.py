#!/usr/bin/env python3
"""Turn the raw files written by adb_collect.sh into a small JSON the report generator can use.

    python3 bench/parse_adb.py results/bench/adb_<label>            -> results/bench/adb_<label>/summary.json
    python3 bench/parse_adb.py --selftest                           -> parses a tiny built-in fixture (checks the parser, NOT a measurement)

Reported (all derived from numbers Android itself reports):
  battery_drop_pct, duration_s, drain_pct_per_hour, temp_start/max/end (deg C; Android reports tenths), thermal_status_max,
  estimated app power (mAh) for the Termux UID if batterystats lists it.
"""
import csv
import json
import os
import re
import sys


def parse_samples(path):
    rows = list(csv.DictReader(open(path)))
    out = []
    for r in rows:
        try:
            out.append({"t": int(r["t_epoch"]), "level": int(r["level"]), "temp_c": int(r["temperature_tenth_c"]) / 10.0, "voltage_mv": int(r["voltage_mv"] or 0),
                        "plugged": (r.get("ac", "").strip().lower() == "true") or (r.get("usb", "").strip().lower() == "true"), "thermal": r.get("thermal_status", "")})
        except (ValueError, KeyError):
            continue
    return out


def parse_batterystats_app_mah(text, package_hint="com.termux"):
    """Find 'Uid u0aNNN: <mAh>' lines and the package->uid map; return mAh for the hinted package or None."""
    uid = None
    m = re.search(r"Package \[%s\].*?\n\s+Uid:?\s*(\S+)" % re.escape(package_hint), text, re.S)
    if m:
        uid = m.group(1)
    if not uid:
        m = re.search(r"%s.*?uid=(\d+)" % re.escape(package_hint), text)
        uid = ("u0a" + str(int(m.group(1)) - 10000)) if m else None
    if not uid:
        return None
    m = re.search(r"Uid\s+%s:\s+([\d.]+)" % re.escape(uid), text)
    return float(m.group(1)) if m else None


def summarise(d):
    s = parse_samples(os.path.join(d, "samples.csv"))
    if len(s) < 2:
        return {"ok": False, "reason": "fewer than 2 samples"}
    dur = s[-1]["t"] - s[0]["t"]
    drop = s[0]["level"] - s[-1]["level"]
    out = {"ok": True, "samples": len(s), "duration_s": dur, "battery_start_pct": s[0]["level"], "battery_end_pct": s[-1]["level"], "battery_drop_pct": drop,
           "drain_pct_per_hour": round(drop / (dur / 3600.0), 2) if dur >= 600 else None,
           "drain_note": "battery % has 1 % resolution: only trust drain rates from runs >= 30 min with >= 3 % drop" if dur >= 600 else "run too short for a drain rate",
           "temp_start_c": s[0]["temp_c"], "temp_max_c": max(x["temp_c"] for x in s), "temp_end_c": s[-1]["temp_c"],
           "plugged_any_sample": any(x["plugged"] for x in s)}
    if out["plugged_any_sample"]:
        out["ok"] = False
        out["reason"] = "device was plugged in during the run - battery numbers are INVALID"
    th = [x["thermal"] for x in s if x["thermal"].isdigit()]
    out["thermal_status_max"] = max(map(int, th)) if th else None
    bs = os.path.join(d, "batterystats.txt")
    if os.path.exists(bs):
        out["termux_app_mah"] = parse_batterystats_app_mah(open(bs, errors="ignore").read())
    for f, k in (("model.txt", "model"), ("abi.txt", "abi"), ("android.txt", "android")):
        p = os.path.join(d, f)
        if os.path.exists(p):
            out[k] = open(p).read().strip()
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        import tempfile
        d = tempfile.mkdtemp()
        open(os.path.join(d, "samples.csv"), "w").write(
            "t_epoch,level,temperature_tenth_c,voltage_mv,status,ac,usb,thermal_status\n"
            "1000,80,310,4100,3,false,false,0\n1900,79,325,4090,3,false,false,0\n2800,78,331,4080,3,false,false,1\n")
        r = summarise(d)
        assert r["ok"] and r["battery_drop_pct"] == 2 and r["temp_max_c"] == 33.1 and r["thermal_status_max"] == 1, r
        print("parse_adb selftest OK:", json.dumps(r))
        sys.exit(0)
    d = sys.argv[1]
    r = summarise(d)
    json.dump(r, open(os.path.join(d, "summary.json"), "w"), indent=1)
    print(json.dumps(r, indent=1))
