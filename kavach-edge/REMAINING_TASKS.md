# What is still owed - only things that need the real phone / real people / your accounts

Phase-1 deadline per the challenge page: **23 Nov 2026**. Order = what a judge notices first. Everything else (code, models, evaluation, offline proof, benchmark harness,
study software, video builder, report builder, tests) is done and reproducible.

| # | Task | Who | Time | How | Done-when |
|---|---|---|---|---|---|
| 1 | **Push to GitHub** (public or judge-accessible) and put the link in the submission | any | 10 min | `git init && git add . && git commit` (`.gitignore` already excludes raw data, study participant CSVs) | repo opens, README renders |
| 2 | **Run the benchmark on the Arm phone** (and a Pi if you have one) | Teammate 2 | 30 min | `bench/BENCHMARK_PROTOCOL.md` sections 2-3: Termux, `pip install numpy`, `python3 bench/run_bench.py --label phone_arm64 --device-note "..." --iters 2000` x3 | `results/bench/bench_phone_arm64.json` exists |
| 3 | **Battery + temperature run** (30 min idle + 30 min load) | Teammate 2 | 70 min, mostly waiting | protocol section 5, `bench/adb_collect.sh`, `parse_adb.py` | `adb_phone_arm64/summary.json`, `adb_phone_idle/summary.json` |
| 4 | **Llama + ExecuTorch advisor** - the PS3 page requires a Llama-family model via ExecuTorch. The detector->evidence->prompt->grounding-check contract is ready (`kavach/advisor.py`); you need the runner | Gautham | 2-4 h (biggest risk) | export a small Llama (e.g. 1B instruct, 4-bit) with ExecuTorch's Llama example, wrap it as `run_llama.sh` (prompt JSON on stdin, text on stdout, last line `{"tokens": N}`), time with `--advisor-cmd` | `advisor.measured: true` in bench JSON; demo shows LLM text beneath template text |
| 5 | **Demo video**: record the phone per `demo/SHOT_LIST.md` (airplane mode first), add voice-over, optionally prepend `demo/video/kavach_edge_explainer.mp4` | Teammate 2 | 1-1.5 h | phone screen recorder + any editor | 3-minute MP4 uploaded |
| 6 | **Phone-level offline proof** | Teammate 2 | 15 min | `offline_proof/PHONE_PROTOCOL.md` A+B | screenshot / pcap in `report/evidence/` |
| 7 | **User study** (8-15 people; 5 minimum as a labelled pilot) | Teammates 1+2 | 3 h for 12 people | `study/PROTOCOL.md`; save CSVs in `study/data/`; `python3 study/analyze_study.py --report [--allow-small]` | `results/STUDY_RESULTS.md` |
| 8 | **Rebuild the report** and export | any | 10 min | `python3 bench/make_report.py && python3 report/build_report.py`; convert `report/TECHNICAL_REPORT.md` to PDF/Word as the portal requires | zero `PENDING` left, or each remaining one is stated as pending |
| 9 | If the Hailo accelerator is used anywhere, document its pipeline separately (challenge rule) | Gautham | - | not used in this repo | n/a |
| 10 | Submit on the portal | Gautham | - | - | confirmation |

## If time runs short (priority cut)
Keep 1, 2, 4 (even a basic LLM explanation), 5, 8. Run the study as a 5-person pilot. Say "pending" in the report for anything not measured - the report generator already does this; never fill a number you did not measure.

## Things to know before a judge asks
* Locked-test false-alarm rate at the *flag* level is high (see report section 3, 7); the product choice is: DANGEROUS blocks, SUSPICIOUS only warns.
* Rule refinements after the first evaluation were guided by errors on the DEV set only; the locked set was not inspected for tuning.
* The network model is trained on NSL-KDD (1999-style); it detects scans/floods well, not payload attacks; pcap tests are synthetic fixtures.
* Arm numbers do not exist until step 2. The x86 numbers in the report are labelled "development reference".
