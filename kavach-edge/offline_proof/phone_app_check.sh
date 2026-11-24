#!/usr/bin/env bash
# Phone-level offline proof for the Kavach Android app (PHONE_PROTOCOL.md parts B and C, non-root version).
# Run from kavach-edge/ with the phone on USB and the debug APK installed.
#
#   ADB=/path/to/adb AAPT=/path/to/aapt APK=../android/app/build/outputs/apk/debug/app-debug.apk bash offline_proof/phone_app_check.sh
#
# What it shows, while the app runs the full pipeline (detector + Llama) on 10 messages:
#   1. the APK requests no INTERNET permission (aapt) and the installed package holds none (dumpsys package);
#   2. the running app process is NOT in Android's inet group (gid 3003). Android grants that group only to apps
#      holding INTERNET, and the kernel refuses internet sockets to processes outside it. An app that has INTERNET
#      (Play Store) is shown for comparison. (The socket tables /proc/<pid>/net/* are blocked by SELinux for
#      run-as on this phone, so they are reported as not verifiable rather than counted as a pass.)
#   3. the kernel's per-UID traffic counters (dumpsys netstats, mAppUidStatsMap) for the app are the same
#      before and after the run.
# Output: report/evidence/phone_offline_<timestamp>.txt
set -u
ADB="${ADB:-adb}"; AAPT="${AAPT:-aapt}"; APK="${APK:-../android/app/build/outputs/apk/debug/app-debug.apk}"
export MSYS_NO_PATHCONV=1
PKG=com.kavach.edge
F=/storage/emulated/0/Android/data/$PKG/files
mkdir -p report/evidence
OUT="report/evidence/phone_offline_$(date +%Y%m%d_%H%M%S).txt"
sh_() { "$ADB" shell "$@" | tr -d '\r'; }
say() { echo "$*" | tee -a "$OUT"; }

say "# Kavach app - phone offline check, $(date '+%F %T')"
say "device: $(sh_ getprop ro.product.model), Android $(sh_ getprop ro.build.version.release), airplane_mode_on=$(sh_ settings get global airplane_mode_on)"
say ""
say "## 1. Permissions"
say "aapt dump permissions $APK:"
"$AAPT" dump permissions "$APK" | tee -a "$OUT"
say "installed package (dumpsys package $PKG), permission lines:"
sh_ dumpsys package $PKG | grep -iE "permission" | tee -a "$OUT"
if "$AAPT" dump permissions "$APK" | grep -q "android.permission.INTERNET"; then say "RESULT 1: FAIL - INTERNET requested"; else say "RESULT 1: PASS - no INTERNET permission requested"; fi
UID_=$(sh_ run-as $PKG id -u)
say "app uid: $UID_"
say ""

say "## 3a. Network byte counters for uid $UID_ BEFORE"
uidstats() { sh_ dumpsys netstats detail | awk -v u="$UID_" '/mAppUidStatsMap/{f=1;next} f&&/^  [^ ]/{f=0} f&&$1==u{print "uid rxBytes rxPackets txBytes txPackets: "$0}'; }
BEFORE=$(uidstats)
say "${BEFORE:-(uid $UID_ has no row in mAppUidStatsMap: no traffic counted since boot)}"
# Parser self-check: the same parser must find a row for an app that does use the network.
VUID=$(sh_ dumpsys package com.android.vending | awk -F'appId=' '/appId=/{print $2; exit}' | awk '{print $1}')
VROW=$(UID_=$VUID uidstats)
say "parser check - Play Store uid $VUID row: ${VROW:-NONE (parser or format problem: treat RESULT 3 as not verifiable)}"
say ""

say "## 2. Sockets held by the app while it runs detector + Llama"
sh_ am force-stop $PKG
sh_ rm -f $F/llm_runs.jsonl
sh_ am start -n $PKG/.MainActivity --es batch /data/local/tmp/kavach/advisor_set.jsonl >/dev/null
sleep 20                                           # model loaded, first messages running
PID=$(sh_ pidof $PKG)
say "pid: $PID"
INODES=$(sh_ run-as $PKG ls -l /proc/$PID/fd 2>/dev/null | grep -o 'socket:\[[0-9]*\]' | grep -o '[0-9]*' | sort -u)
say "socket inodes in /proc/$PID/fd: $(echo $INODES | wc -w)"
APP_GROUPS=$(sh_ run-as $PKG cat /proc/$PID/status | awk '/^Groups:/{$1="";print}')
say "app process groups:$APP_GROUPS"
VP=$(sh_ pidof com.android.vending | awk '{print $1}')
[ -n "$VP" ] && say "for comparison, Play Store (has INTERNET) groups:$(sh_ cat /proc/$VP/status | awk '/^Groups:/{$1="";print}')"
if [ -z "$APP_GROUPS" ]; then say "RESULT 2: NOT VERIFIABLE - could not read the process groups"
elif echo " $APP_GROUPS " | grep -q " 3003 "; then say "RESULT 2: FAIL - app process is in the inet group (3003)"
else say "RESULT 2: PASS - app process is not in the inet group (3003): the kernel will not give it an internet socket"; fi
if sh_ run-as $PKG cat /proc/$PID/net/tcp >/dev/null 2>&1 && [ -n "$(sh_ run-as $PKG cat /proc/$PID/net/tcp 2>/dev/null)" ]; then
  say "socket tables readable (not used for the result)"
else
  say "socket tables /proc/$PID/net/*: NOT VERIFIABLE on this phone (permission denied for run-as)"
fi
# let the batch finish
for t in $(seq 1 60); do n=$(sh_ "cat $F/llm_runs.jsonl 2>/dev/null | wc -l"); [ "${n:-0}" -ge 10 ] && break; sleep 5; done
say "batch finished: $(sh_ "cat $F/llm_runs.jsonl | wc -l") messages explained by Llama"
say ""

say "## 3b. Network byte counters for uid $UID_ AFTER"
AFTER=$(uidstats)
say "${AFTER:-(uid $UID_ has no row in mAppUidStatsMap: no traffic counted since boot)}"
if [ "$BEFORE" = "$AFTER" ]; then say "RESULT 3: PASS - byte counters unchanged"; else say "RESULT 3: CHECK - counters differ (inspect above)"; fi
sh_ am force-stop $PKG
say ""
say "saved: $OUT"
