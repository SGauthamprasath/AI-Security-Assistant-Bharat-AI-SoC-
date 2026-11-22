# Kavach-Edge benchmark protocol (v1.0)

Purpose: produce **measured** latency, memory, battery and temperature numbers that a judge can reproduce. Every number in the
report's *Hardware & Performance* section must trace back to a JSON/CSV file produced by the commands below. Nothing is estimated.

## 0. Rules (these are what make the numbers credible)
1. **Same code, same command, every device.** Only `--label` and `--device-note` change.
2. **Arm numbers only from Arm hardware.** `run_bench.py` records `platform.machine()`; anything not `aarch64/arm*` is tagged
   `reference_only` and the report generator prints it in a separate "development reference (x86, not Arm)" table.
3. **Report medians AND tails** (p50 / p95 / p99). Averages hide the stalls a user actually feels.
4. **Cold start is reported separately** from steady state (fresh process, 5 repeats).
5. **Battery/temperature need a long window.** Android battery % has 1 % resolution; use >= 30 min and report the drop, the
   duration and the idle baseline. A run during which the charger was connected is rejected automatically by `parse_adb.py`.
6. **Record the conditions** in `--device-note`: model, SoC, Android/OS version, RAM, battery % at start, screen state,
   airplane mode, charger, ambient temperature if known, other apps running.
7. **Don't cherry-pick.** Keep every run's JSON in `results/bench/`; the report uses the *median of the 3 runs* per device.

## 1. Devices (fill in what you actually have; minimum = one Arm device)
| Tag | Device | Role |
|---|---|---|
| `phone_arm64` | the team phone (Snapdragon / Dimensity / Tensor / Exynos, Android) | primary target: "on-device" claim |
| `rpi5_arm64` (optional) | Raspberry Pi 4/5 (Cortex-A72/A76), network-monitor node | home-router / gateway scenario |
| `sandbox_x86` | already measured in this repo | development reference only |

## 2. Setup on the device
Android (Termux from F-Droid, not the Play Store build):
```bash
pkg update && pkg install python python-numpy scipy clang   # scapy only needed for pcap analysis: pip install scapy
git clone <your repo> kavach-edge && cd kavach-edge && pip install -r requirements.txt
```
Raspberry Pi OS: `sudo apt install python3-numpy python3-scipy python3-pandas && pip install scapy`.
Nothing else is needed - the detector is NumPy-only at runtime (no sklearn, no ONNX Runtime, no network).

## 3. Latency, memory, footprint  (5-10 minutes)
```bash
python3 bench/run_bench.py --label phone_arm64 --device-note "<model>, Android <ver>, <RAM>, battery <pct>%, screen off, airplane on" --iters 2000
```
Repeat 3 times (reboot the phone between runs 1 and 2 to also capture a true cold boot). Produces `results/bench/bench_<label>.json`.
Reported fields: cold start (load + first verdict), per-stage and end-to-end latency p50/p90/p95/p99, URL latency, throughput,
RSS and **PSS** (proportional set size - what the OS actually charges the process), model bytes, pcap connections/s.

## 4. Advisor (Llama + ExecuTorch) timing
The grounded advisor prompt is built by `kavach/advisor.py`. To time the real LLM on the device, wrap your ExecuTorch runner in a
script that reads the prompt JSON on stdin, streams the answer on stdout and ends with a line `{"tokens": N}`, then:
```bash
python3 bench/run_bench.py --label phone_arm64 --iters 500 --advisor-cmd "./run_llama.sh" --advisor-samples 10
```
Reported: time-to-first-token (ttfb), total generation time, tokens/s, memory after the LLM ran. Until this is run the report says
**NOT MEASURED** - it never fills a guess.

## 5. Battery & temperature (the long run)
Two runs of identical length (30 min recommended): **idle baseline** and **workload**.
1. Charge to >= 60 %, unplug, enable airplane mode, connect `adb` over Wi-Fi (`adb tcpip 5555; adb connect <ip>:5555`, remove cable).
2. Idle baseline: `bash bench/adb_collect.sh phone_idle 1800` (phone does nothing, screen off).
3. Workload: start `bash bench/adb_collect.sh phone_arm64 1800` on the laptop and, at the same moment, in Termux:
   `python3 bench/run_bench.py --label phone_arm64 --skip-cold --iters 500 --sustained-seconds 1800`
   (`termux-wake-lock` first so Android doesn't sleep the process).
4. `python3 bench/parse_adb.py results/bench/adb_phone_arm64` and the same for `adb_phone_idle`.
Reported: battery % drop, drain %/h with idle drain subtracted, temperature start/max/end, thermal status, latency drift between
first and last minute (throttling), battery % per 1000 verdicts.
Without adb: `python3 bench/sysmon.py --seconds 1800` inside Termux (needs Termux:API for battery) or use the Pi's `vcgencmd` data
that `run_bench.py` already collects.

## 5b. Raspberry Pi
Same commands; `sysmon.py` reads `vcgencmd measure_temp` and `get_throttled`. Report the throttled flag (`0x0` = none).
Use a stopwatch-free approach: `--sustained-seconds 1800`.

## 6. Generating the report section
```bash
python3 bench/make_report.py            # writes report/sections/05_hardware_performance.md + results/figs/latency_*.png
```
Missing measurements appear as **PENDING** rows listing the exact command to run. Re-run after each new device file lands.

## 7. Acceptance targets (what we claim, and what "pass" means)
| Metric | Target | Why |
|---|---|---|
| Message verdict p95 | < 50 ms on the phone | feels instant in an SMS/notification flow |
| Cold start (load + first verdict) | < 1 s | works after reboot / when the service is relaunched |
| RSS (detector only) | < 150 MB | leaves RAM for the LLM |
| Detector model files | < 10 MB | tiny relative to the on-device LLM |
| Battery for 1000 verdicts | report, no target | typical user receives << 1000 messages/day |
| Temperature rise in 30 min | < 5 C over idle | no thermal throttling |
Missing a target is reported as missed.
