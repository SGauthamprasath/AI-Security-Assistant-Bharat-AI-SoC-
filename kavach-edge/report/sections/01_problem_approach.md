# 1. Problem, threat model and approach

**Problem.** Indians receive a constant stream of scam SMS/WhatsApp messages and phishing links; cloud-based filters need connectivity, send message content to a server, and are
unavailable exactly when a user is on a weak network. Home and small-office networks are also scanned and flooded with no tooling visible to the user.

**Threat model.** (1) Messages that impersonate banks, government, delivery or utilities and push the user to click, call or share credentials; (2) links whose address imitates a known brand or
uses throw-away hosting; (3) hostile traffic on the local network (reconnaissance scans, SYN floods, ICMP floods, smurf-style reflections). Out of scope: malware analysis, payload-level attacks hidden in
encrypted traffic, voice calls.

**Design principles.** (a) *Private by construction* - no network code in the detector package, verified automatically. (b) *Small and fast* - NumPy-only runtime so it is designed to run on Termux/Pi with no native
ML runtime (install on-device still to be verified, see section 5). (c) *Explainable* - every verdict is a sum of named, signed contributions. (d) *Low false alarms* - thresholds are set from a false-alarm budget; trusted domains and genuine
OTP/transaction notices are modelled explicitly, because a guard people switch off protects nobody. (e) *Honest evaluation* - locked test sets and confidence intervals.

**Architecture.**
```
SMS / chat text ──► normalise ─► wording model (hashed n-grams, Platt-calibrated) ─┐
                         └────► 19 scam + 5 genuine-notice rules ───────────────────┤
links in text / URL ───► host model (trees + n-grams) + brand/look-alike/TLD rules ─┼─► constrained stacker ─► risk 0-1 ─► SAFE / SUSPICIOUS / DANGEROUS
pcap / live flows ─────► connection rebuilder ─► KDD window features ─► tree model ─┘                         │
                                                                                                           ▼
                                                           Evidence JSON (kavach.evidence/1.0, no raw text) ─► UI  and  on-device LLM explainer (grounded)
```
Models: `sms_lr.bin` (1 MB float32 weights), `url_hgb.npz` + `url_ngram.bin`, `net_hgb.npz`, `fusion.json`; trees are exported to flat arrays and evaluated by a ~40-line NumPy runtime (bit-level
parity with scikit-learn, 7e-15) because ONNX export of histogram gradient boosting is not supported and ONNX Runtime is awkward on Termux.
