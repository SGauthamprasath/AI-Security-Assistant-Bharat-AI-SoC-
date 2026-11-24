#!/usr/bin/env bash
# Full phone benchmark for the Kavach Android app (protocol: bench/BENCHMARK_PROTOCOL.md, sections 3-4).
# Run from kavach-edge/ on the laptop with the phone on USB. It needs only adb over the cable, not
# internet, so the phone can be switched to airplane mode right after it starts.
#
#   ADB=/path/to/adb bash bench/phone_run_all.sh
#
# Prerequisites: the app is installed; files/kbench on the phone holds bench/, data/, models/, demo/pcaps/
# (pushed earlier); the phone is unlocked with the Kavach app allowed to keep the screen on.
#
# Phases: conditions -> cold start x5 -> run_bench.py x3 (Llama NOT loaded) -> Llama advisor x3 (10 scam
# messages each) -> pull everything into results/bench/ and fill cold_start + advisor blocks.
set -u
ADB="${ADB:-adb}"
export MSYS_NO_PATHCONV=1
PKG=com.kavach.edge
F=/storage/emulated/0/Android/data/$PKG/files
K=$F/kbench
OUT="${OUT:-results/bench}"
LABEL="${LABEL:-phone_arm64}"
RUNS="${RUNS:-1 2 3}"      # set RUNS=1 for a quick check
COOL="${COOL:-90}"          # seconds of cool-down between runs
mkdir -p "$OUT"
LOG=$OUT/phone_run_all.log

log() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }
sh_() { "$ADB" shell "$@" | tr -d '\r'; }

conditions() {   # one line: airplane, swap, battery, temperature, power, brightness, uptime
  local air swap lvl tmp usb ac bm up
  air=$(sh_ settings get global airplane_mode_on)
  swap=$(sh_ "grep SwapTotal /proc/meminfo" | awk '{print int($2/1024)}')
  lvl=$(sh_ dumpsys battery | awk -F': ' '/^ *level:/{print $2}')
  tmp=$(sh_ dumpsys battery | awk -F': ' '/^ *temperature:/{print $2/10}')
  usb=$(sh_ dumpsys battery | awk -F': ' '/USB powered:/{print $2}')
  ac=$(sh_ dumpsys battery | awk -F': ' '/AC powered:/{print $2}')
  bm=$(sh_ settings get system screen_brightness_mode)
  up=$(sh_ cat /proc/uptime | awk '{printf "%.0f", $1/60}')
  echo "airplane=$air swap_mb=$swap battery=${lvl}% batt_temp=${tmp}C usb_power=$usb ac_power=$ac brightness_auto=$bm uptime_min=$up"
}

wait_lines() {   # wait_lines <remote file> <n> <timeout s>
  local t=0
  while [ "$t" -lt "$3" ]; do
    n=$(sh_ "cat $1 2>/dev/null | wc -l"); [ "${n:-0}" -ge "$2" ] && return 0
    sleep 5; t=$((t + 5))
  done
  return 1
}

wait_file() {    # wait_file <remote file> <timeout s>
  local t=0
  while [ "$t" -lt "$2" ]; do
    sh_ "ls $1" >/dev/null 2>&1 && [ -n "$(sh_ "ls $1 2>/dev/null")" ] && return 0
    sleep 5; t=$((t + 5))
  done
  return 1
}

"$ADB" get-state >/dev/null || { echo "no device"; exit 1; }
MODEL=$(sh_ getprop ro.product.model); ANDROID=$(sh_ getprop ro.build.version.release)
OS=$(sh_ getprop ro.vivo.os.build.display.id)
C0=$(conditions)
NOTE="Vivo V40e ($MODEL), MediaTek Dimensity 7300, 8 GB RAM, Android $ANDROID ($OS); Kavach app, detector via Chaquopy (Python 3.12, NumPy 1.26.2) in the app process; screen on, app in foreground, phone on USB; Extended RAM ${EXT_RAM:-unknown}"
log "START  $NOTE | $C0"
# Time for the user to switch airplane mode ON (the laptop loses its tethered internet; adb over USB keeps working).
log "switch airplane mode ON now - waiting ${START_DELAY:-60}s"; sleep "${START_DELAY:-60}"
log "conditions after wait: $(conditions)"

# ---------------------------------------------------------------- 1. cold start x5
log "phase 1: cold start x5"
sh_ rm -f $F/coldstart.jsonl
: > "$OUT/coldstart_am_$LABEL.txt"
for i in ${COLD_N:-1 2 3 4 5}; do
  sh_ am force-stop $PKG; sleep 5
  tt=$(sh_ am start -W -n $PKG/.MainActivity --ez coldstart true | awk -F': ' '/TotalTime/{print $2}')
  echo "am_start_TotalTime_ms=$tt" >> "$OUT/coldstart_am_$LABEL.txt"
  wait_lines $F/coldstart.jsonl $i 60 || log "  cold start $i: TIMEOUT"
  log "  cold start $i done (am TotalTime ${tt} ms)"
done
"$ADB" pull $F/coldstart.jsonl "$OUT/coldstart_$LABEL.jsonl" >/dev/null

# ---------------------------------------------------------------- 2. run_bench.py x3 (no Llama)
for r in $RUNS; do
  log "phase 2: run_bench run $r - cool-down ${COOL}s"; sleep "$COOL"
  sh_ am force-stop $PKG
  sh_ rm -f $K/results/bench/bench_$LABEL.json
  NOTE_R="$NOTE; conditions at run start: $(conditions) (run $r of 3)" ITERS="${ITERS:-2000}" python -c "
import json,os
json.dump(['--label','$LABEL','--iters',os.environ['ITERS'],'--skip-cold','--device-note',os.environ['NOTE_R']],
          open('$OUT/run_args.tmp.json','w',encoding='utf-8'))"
  "$ADB" push "$OUT/run_args.tmp.json" $K/bench_args.json >/dev/null
  sh_ am start -n $PKG/.MainActivity --es bench_args_file $K/bench_args.json >/dev/null
  if wait_file $K/results/bench/bench_$LABEL.json 1200; then
    sleep 3
    "$ADB" pull $K/results/bench/bench_$LABEL.json "$OUT/bench_${LABEL}_run$r.json" >/dev/null
    log "  run $r saved -> $OUT/bench_${LABEL}_run$r.json | $(conditions)"
  else
    log "  run $r: TIMEOUT (no bench json after 1200 s) | $(conditions)"
  fi
done
"$ADB" pull $K/results/bench/stdout.txt "$OUT/run_bench_stdout_$LABEL.txt" >/dev/null 2>&1

# ---------------------------------------------------------------- 3. Llama advisor x3
# Same selection as run_bench --advisor-samples 10: the first 10 scam (label 1) messages of the corpus.
python -c "
import json
rows=[json.loads(l) for l in open('data/kavachbench_in.jsonl',encoding='utf-8')]
sc=[r for r in rows if r['label']==1][:10]
with open('$OUT/advisor_set.jsonl','w',encoding='utf-8') as f:
    for i,r in enumerate(sc): f.write(json.dumps({'id':f'adv{i+1:02d}','text':r['text'],'sender':r.get('sender')},ensure_ascii=False)+'\n')
"
sh_ mkdir -p /data/local/tmp/kavach
"$ADB" push "$OUT/advisor_set.jsonl" /data/local/tmp/kavach/ >/dev/null
sh_ chmod 644 /data/local/tmp/kavach/advisor_set.jsonl
for r in $RUNS; do
  log "phase 3: Llama run $r - cool-down ${COOL}s"; sleep "$COOL"
  sh_ am force-stop $PKG
  sh_ rm -f $F/llm_runs.jsonl
  sh_ am start -n $PKG/.MainActivity --es batch /data/local/tmp/kavach/advisor_set.jsonl >/dev/null
  if wait_lines $F/llm_runs.jsonl 10 900; then
    "$ADB" pull $F/llm_runs.jsonl "$OUT/llm_runs_${LABEL}_run$r.jsonl" >/dev/null
    [ -f "$OUT/bench_${LABEL}_run$r.json" ] && python bench/llm_from_app.py --runs "$OUT/llm_runs_${LABEL}_run$r.jsonl" \
        --bench "$OUT/bench_${LABEL}_run$r.json" | tee -a "$LOG"
    log "  Llama run $r saved | $(conditions)"
  else
    log "  Llama run $r: TIMEOUT | $(conditions)"
  fi
done
sh_ am force-stop $PKG

# ---------------------------------------------------------------- 4. cold start into the bench files
ls "$OUT"/bench_${LABEL}_run*.json >/dev/null 2>&1 && \
  python bench/coldstart_from_app.py --samples "$OUT/coldstart_$LABEL.jsonl" "$OUT"/bench_${LABEL}_run*.json | tee -a "$LOG"
log "ALL DONE | $(conditions)"
