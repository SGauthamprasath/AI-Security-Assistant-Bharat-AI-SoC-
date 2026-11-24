# Kavach-Edge: on-device scam guard with a Llama advisor

*Bharat AI-SoC Challenge 2026-27, Problem Statement 3 (cybersecurity and digital safety).*

Kavach-Edge checks an SMS or a link **entirely on an Arm Android phone**. A small explainable detector decides the
verdict; **Llama 3.2 1B running on the phone's CPU through ExecuTorch** explains it in plain words. No cloud, no server,
and the app does not have the Android INTERNET permission.

```
SMS / link -> detector (wording model + scam rules + link checks) -> risk fusion -> evidence JSON
           -> Llama 3.2 1B (ExecuTorch, CPU) -> output checks -> explanation + steps from a fixed playbook
```

* **The detector decides; Llama only explains.** The verdict (safe / suspicious / dangerous) comes from risk fusion and is
  shown before Llama starts. Llama never sees the message text - only the detector's facts - and cannot change the verdict.
* **Llama's text is checked before it is shown** (invented phone numbers or links, contradicting the verdict, certainty
  claims, topics with no supporting evidence). If a check fails, the app shows a deterministic template instead.
* **The action steps never come from the model**: they are taken word for word from a fixed remediation playbook.

Full write-up: [`kavach-edge/report/TECHNICAL_REPORT.md`](kavach-edge/report/TECHNICAL_REPORT.md).

## Measured results (Vivo V40e, MediaTek Dimensity 7300, 8 GB RAM, Android 16)

| What | Result | Source |
|---|---|---|
| Verdict time per SMS, in the app | 1.54 ms median, 3.59 ms p95 (3 runs x 2000 messages) | `kavach-edge/results/bench/bench_phone_arm64_run*.json` |
| Llama 3.2 1B (SpinQuant INT4) | first token 2.6 s, 14.5 tokens/s, full explanation 5.7 s (median, 3 runs x 10 scam messages) | same files, `advisor` block |
| App memory | 117 MB PSS for the detector; about 1.86 GB peak with Llama loaded | same files |
| Scam detection, hand-written locked test (never tuned on) | 86 % of scams flagged at 12.5 % false alarms; 80 % at 8.3 % when blocking | `kavach-edge/results/metrics.json` |
| Prompt injection (30 synthetic attacks) | 0 attacks lowered a verdict; 0 reached the Llama prompt; on the phone Llama never followed one | `kavach-edge/results/injection.json` |
| Offline on the phone | no INTERNET permission; app process outside Android's `inet` group; no traffic counted for the app's UID | `kavach-edge/report/evidence/phone_offline_*.txt` |

Read with the report: the phone benchmarks were run with airplane mode **off** (the phone was tethering the laptop) and on
USB power; the 30-minute battery/temperature run and the user study are still pending. Details and limitations are in
sections 5 and 7 of the report.

## Repository layout

```
android/        Android app (Kotlin). Thin: calls Python for the verdict and prompt, runs Llama, shows the result.
  app/src/main/java/com/kavach/edge/   MainActivity.kt (UI, threads, dev hooks), LlamaAdvisor.kt (ExecuTorch LlmModule)
  app/src/main/python/kavach_bridge.py  prompt in Llama 3 chat format, output checks, fallback, benchmark hooks
kavach-edge/    the detector and everything around it (see kavach-edge/README.md)
  kavach/       the detector package - the ONLY copy; the Android build copies it into the APK at build time
  models/       detector model files (3.6 MB)
  tests/        pytest suite, incl. test_android_bridge.py and test_prompt_injection.py
  bench/ report/ offline_proof/ demo/ data/ results/ scripts/ study/
```

The detector runs on the phone through **Chaquopy** (embedded Python 3.12 + NumPy 1.26.2), unchanged. On 292 development
messages and links, phone and laptop gave identical verdicts, categories and risk scores.

## 1. Get the Llama model (not in this repository)

Model weights and the tokenizer are **not committed** (see `.gitignore`). They are covered by the
[Llama 3.2 Community License](https://www.llama.com/llama3_2/license/); accept it on Hugging Face when asked.

Files used (pre-exported for ExecuTorch by the `executorch-community` organisation on Hugging Face):

| File | From | Size |
|---|---|---|
| `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte` | `executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET` | about 1.1 GB |
| `tokenizer.model` | same repository (Llama 3 tokenizer) | about 2.2 MB |

```bash
pip install -U huggingface_hub
huggingface-cli login          # your own token; never commit it
huggingface-cli download executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET \
    Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte tokenizer.model --local-dir llama
```

Push them to the phone (USB debugging on). The app reads them from this folder; they are not inside the APK:

```bash
adb shell mkdir -p /data/local/tmp/llama
adb push llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte /data/local/tmp/llama/
adb push llama/tokenizer.model /data/local/tmp/llama/
```

The app was tested with `org.pytorch:executorch-android:1.1.0`. A `.pte` exported with a different ExecuTorch version
may not load.

## 2. Build and install the app

Needs: JDK 17+ (Android Studio's bundled JBR works), Android SDK platform 35, and **Python 3.12** on the build machine
(Chaquopy compiles the app's Python with it). The build machine needs internet once to download Gradle plugins, Chaquopy's
NumPy wheel and the ExecuTorch AAR; the app itself never uses the network.

```bash
cd android
# create local.properties with your SDK path, e.g.  sdk.dir=C\:\\Users\\<you>\\AppData\\Local\\Android\\Sdk
./gradlew assembleDebug                      # Windows: gradlew.bat assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The `stageDetector` Gradle task copies `kavach-edge/kavach` and `kavach-edge/models` into the build folder; nothing else
from `kavach-edge/` goes into the APK. Check the permissions of the built APK:

```bash
aapt dump permissions app/build/outputs/apk/debug/app-debug.apk    # no android.permission.INTERNET
```

## 3. Use it

Open **Kavach Edge**, paste an SMS (and optionally the sender) or a link, and tap **Check** - a single web address is
checked as a link, anything else as an SMS (the hint under the box says which). The verdict card appears at once; Llama's
explanation streams in grey in the "Why" card and is replaced by the checked text, with a chip saying whether it came from
Llama on the phone or from the fixed template; the "What to do" steps come from the playbook. Llama loads in about 4-7 s when the
app opens. Keep the app on screen: the phone's OS freezes apps that leave the screen.

Demo messages: `kavach-edge/demo/demo_messages.txt`. Demo script: `kavach-edge/demo/SHOT_LIST.md`.

## 4. Reproduce the numbers

From `kavach-edge/` (Windows: prefix Python commands with `PYTHONUTF8=1`):

| Claim | Command |
|---|---|
| Tests (136; includes bridge and prompt-injection tests) | `python -m pytest -q tests` |
| Detection accuracy | `python scripts/06_evaluate.py` |
| Offline proof (laptop) | `python offline_proof/verify_offline.py` (step 4/4 needs Linux `unshare`) |
| Offline proof (phone) | `bash offline_proof/phone_app_check.sh` |
| Phone benchmarks | `bash bench/phone_run_all.sh` (phone on USB, app installed, files pushed - see the script header) |
| Prompt-injection results | `python scripts/eval_injection.py` |
| Report | `python bench/make_report.py && python scripts/eval_injection.py && python report/build_report.py` |

On Windows, `test_runtime_offline_proof_passes` fails because its last step needs Linux `unshare`; the other 135 pass.

## Limits (short version)

Hand-written test sets are small and synthetic messages are templated; detection is English/Hinglish only; Llama 3.2 1B
follows instructions loosely and the output checks are pattern-based, so they also reject some harmless text; the app
needs about 1.9 GB of RAM with Llama loaded. The report's section 7 lists all of them. Predictions can be wrong: never tap
links in suspicious messages, and if you lost money call **1930** (National Cyber Crime Helpline) or report at
cybercrime.gov.in.

## Licences

Code: see repository licence. Llama 3.2 is licensed under the Llama 3.2 Community License (Meta); the model files are not
redistributed here. Datasets are listed in `kavach-edge/README.md`.
