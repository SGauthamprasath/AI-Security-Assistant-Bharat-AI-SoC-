#!/usr/bin/env bash
# Collect battery / thermal / power evidence from an Android phone over adb while Kavach-Edge runs ON the phone (Termux).
#
#   bash bench/adb_collect.sh <label> <duration_seconds>      e.g.  bash bench/adb_collect.sh pixel8_arm64 1800
#
# Protocol (see bench/BENCHMARK_PROTOCOL.md section 5):
#   1. Phone unplugged from the charger (adb over Wi-Fi: `adb tcpip 5555; adb connect <ip>:5555`, then unplug USB), screen off after launch,
#      airplane mode ON (Wi-Fi may stay on for adb only), battery >= 60 %, brightness irrelevant (screen off).
#   2. Run this script on the laptop; at t=0 start the workload on the phone in Termux:
#         python3 bench/run_bench.py --label <label> --sustained-seconds <duration> --skip-cold
#   3. The script resets the Android batterystats, samples `dumpsys battery` + thermal every 10 s, and dumps batterystats at the end.
# Baseline: run once with the SAME duration and NO workload (idle) so the report can subtract idle drain.
set -euo pipefail
LABEL="${1:?label}"; DUR="${2:?duration seconds}"
OUT="results/bench/adb_${LABEL}"; mkdir -p "$OUT"
command -v adb >/dev/null || { echo "adb not found (install Android platform-tools)"; exit 1; }
adb get-state >/dev/null

adb shell getprop ro.product.model        > "$OUT/model.txt"
adb shell getprop ro.product.cpu.abi      > "$OUT/abi.txt"
adb shell getprop ro.build.version.release> "$OUT/android.txt"
adb shell cat /proc/cpuinfo               > "$OUT/cpuinfo.txt" || true
adb shell dumpsys battery set status 1 >/dev/null 2>&1 || true     # no-op on most builds; harmless
adb shell dumpsys batterystats --reset    >/dev/null
echo "t_epoch,level,temperature_tenth_c,voltage_mv,status,ac,usb,thermal_status" > "$OUT/samples.csv"
START=$(date +%s)
while [ $(( $(date +%s) - START )) -lt "$DUR" ]; do
  B=$(adb shell dumpsys battery)
  lvl=$(echo "$B"  | awk -F': ' '/^ *level:/{print $2}' | tr -d '\r')
  tmp=$(echo "$B"  | awk -F': ' '/^ *temperature:/{print $2}' | tr -d '\r')
  vol=$(echo "$B"  | awk -F': ' '/^ *voltage:/{print $2}' | tr -d '\r')
  sta=$(echo "$B"  | awk -F': ' '/^ *status:/{print $2}' | tr -d '\r')
  ac=$(echo "$B"   | awk -F': ' '/AC powered:/{print $2}' | tr -d '\r')
  usb=$(echo "$B"  | awk -F': ' '/USB powered:/{print $2}' | tr -d '\r')
  ths=$(adb shell dumpsys thermalservice 2>/dev/null | awk -F'=' '/Thermal Status:/{print $2}' | tr -d '\r ' | head -1)
  echo "$(date +%s),$lvl,$tmp,$vol,$sta,$ac,$usb,${ths:-}" >> "$OUT/samples.csv"
  sleep 10
done
adb shell dumpsys batterystats           > "$OUT/batterystats.txt"
adb shell dumpsys thermalservice         > "$OUT/thermalservice.txt" 2>/dev/null || true
adb shell dumpsys battery                > "$OUT/battery_end.txt"
echo "done -> $OUT ; now run:  python3 bench/parse_adb.py $OUT"
