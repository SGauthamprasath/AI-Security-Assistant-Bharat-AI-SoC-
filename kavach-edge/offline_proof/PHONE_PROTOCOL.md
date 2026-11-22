# Phone-level offline proof (10 minutes, run on the real device)

The laptop/sandbox proof (`verify_offline.py`) shows the *code* never touches the network. Judges also like to *see* it on the phone.
Do all three; screenshots/recording go into `report/evidence/`.

## A. Airplane-mode demo (visual, 60 s - also the opening of the demo video)
1. Pull down the status bar: **Airplane mode ON**, Wi-Fi OFF, mobile data OFF. Keep the status bar visible in the recording.
2. Open the Kavach-Edge demo (Termux: `python3 demo/app.py` -> browser at `localhost:8000`, or the Android app if integrated).
3. Paste 3 messages: one obvious scam with a link, one genuine bank OTP, one network pcap (`demo/pcaps/port_scan.pcap`). Show the verdict, the
   reasons, the plain-language advice (and the on-device LLM advice if ExecuTorch is integrated).
4. Say out loud: "No SIM data, no Wi-Fi, no server - this is the model running on the Arm CPU."

## B. Zero-packets proof with tcpdump (rooted phone / Raspberry Pi) or PCAPdroid (non-root)
Rooted / Pi:
```bash
sudo tcpdump -i any -w offline_run.pcap &        # capture everything on every interface
python3 bench/run_bench.py --label phone_arm64 --skip-cold --iters 500
sudo kill %1 ; tcpdump -nn -r offline_run.pcap | wc -l
```
Expected: only packets that are not from our process (OS background traffic if radios are on). With airplane mode ON the count is 0-few
(ARP/mDNS on loopback-less setups). To attribute packets to a process use `ss -tpn` / `lsof -i` during the run - the Kavach process must have **no** sockets:
```bash
ls -l /proc/$(pgrep -f run_bench.py)/fd | grep -c socket     # expect 0 (or only AF_UNIX/NETLINK, never INET)
```
Non-root Android: install **PCAPdroid** (F-Droid), start a capture with filter "Termux", run the workload, show "0 connections" for the app.

## C. adb byte counters (per-app, Android)
```bash
adb shell dumpsys netstats detail | grep -A4 "uid=$(adb shell stat -c %u /data/data/com.termux)"   # before and after
```
Bytes before == bytes after for the Termux UID during the run (mobile + Wi-Fi). Save both outputs.

## D. What to claim
"With airplane mode on and no sockets opened by the process, the detector produced identical verdicts (same SHA-256 verdict digest as the
connected run) - verified statically, at runtime, in an empty network namespace, and on the device."
Compare `verdict_digest` printed by `verify_offline.py` (laptop) with the one from the phone run (`python3 offline_proof/verify_offline.py` on the phone gives the same digest if the models are byte-identical).
