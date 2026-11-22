# Demo video - shot list and narration (target 3:00, record on the REAL phone)

`demo/video/kavach_edge_explainer.mp4` (68 s, silent, captioned) is already built from real pipeline output: use it as the intro/explainer cut or as backup.
The *judged* demo should be your screen recording on the Arm device. Record with the phone's screen recorder; keep the status bar visible.
Record narration separately (phone voice recorder, quiet room) and lay it over in any editor (CapCut / DaVinci / ffmpeg). Subtitles: reuse captions below.

| # | Time | On screen | Say (read naturally, ~140 words/min) |
|---|---|---|---|
| 1 | 0:00-0:12 | Title card from the explainer video | "Every year Indians lose thousands of crores to SMS and link scams, and home networks are scanned constantly. Kavach-Edge is a guard that runs entirely on your phone's Arm CPU." |
| 2 | 0:12-0:35 | Pull down status bar: **Airplane mode ON**, Wi-Fi off, data off. Show device model (Settings > About) for 2 s | "I am switching on airplane mode. Nothing you will see now can use the internet. The model bundle is 3.6 megabytes." |
| 3 | 0:35-1:15 | Paste the SBI KYC scam. Show DANGEROUS, bars of evidence, advice | "A fake bank KYC message with a look-alike link. Kavach combines a wording model, scam rules and link analysis. Red bars are reasons; the advice is in plain words." |
| 4 | 1:15-1:35 | Paste genuine OTP message -> SAFE | "A real OTP notice is recognised as safe. Avoiding false alarms matters as much as catching scams." |
| 5 | 1:35-1:55 | Paste `https://amaz0n-in-support.top/...` then `https://www.amazon.in/...` | "The look-alike Amazon address is flagged from the address alone. The real one is trusted." |
| 6 | 1:55-2:25 | Open `demo/pcaps/mixed_home_network.pcap` (or live capture on Pi) -> port scan + SYN flood alerts | "The same engine reads a packet capture. It rebuilds connections and recognises a port scan and a SYN flood from header statistics, without looking at content." |
| 7 | 2:25-2:45 | Terminal: `python3 bench/run_bench.py ...` summary line on the phone (REAL numbers) | "On this phone a verdict takes <p50> ms median, <p95> ms at the 95th percentile, using <rss> MB of RAM." (fill with your measured values) |
| 8 | 2:45-3:00 | Results slide (frame 08 of the explainer) | "On messages we wrote by hand and never tuned on, it catches 84 percent at a 15 percent false-alarm rate, 80 percent at 4 percent when blocking. We publish our weaknesses too. Thank you." |

## Checklist before recording
* Battery > 60 %, brightness medium, Do-Not-Disturb ON (no notifications in the recording).
* Run `python3 demo/app.py` in Termux, open `http://localhost:8000` in Chrome (works in airplane mode).
* Rehearse once; keep a 5-second pause before/after each paste so cuts are easy.
* If the Llama + ExecuTorch advisor is integrated: add a shot after #3 showing the model's explanation under the template one and its tokens/s from `run_bench.py --advisor-cmd`.
* Never read a number you did not measure.
