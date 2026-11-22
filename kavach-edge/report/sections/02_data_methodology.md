# 2. Data and methodology

**Message data.** UCI SMS Spam Collection; user-reported smishing from the IMC 2025 study (Agarwal et al., CC BY 4.0; India-heavy); and synthetic genuine Indian messages (bank/UPI notices, OTPs,
orders, appointments, chat in English/Hinglish) generated from templates, because public corpora contain very few genuine Indian transactional messages. Reported smishing contains some genuine
OTP/bank notices that users forwarded; a label-noise filter removes reported messages that match genuine-notice patterns.
**URL data.** Phishing.Database active links (positives); Tranco top-1M (benign hosts, trusted allow-list); OpenDNS top domains (an independent benign set used only for a false-alarm check).
**Network data.** NSL-KDD with the official KDDTrain+/KDDTest+ split. Only the 28 features computable from packet headers are used (9 basic, 9 two-second window, 10 host window); the 13 payload-content
features are dropped - this lets the same features be rebuilt from a live capture or a pcap, and works on encrypted traffic.

**Leakage controls** (the usual way scam detectors get inflated numbers):
* SMS train/validation/test are split by *skeleton group* (text with digits/URLs/names masked), so near-duplicate templates never straddle splits; synthetic genuine messages are split by row.
* URLs are split by *registered domain* (shared-hosting platforms such as `*.github.io` by full host), so the model cannot memorise a domain.
* The URL model sees the host only (no path/query) to avoid source shortcuts between the phishing feed and the benign list; path features appear only in the rule layer.
* TLD phishing rates are computed from the training split only. The shared-hosting list is derived from the data (>=40 hosts per registered domain).
* Fusion and thresholds are fitted on validation composites plus the DEV hand-written benchmark. A second hand-written benchmark (**LOCKED TEST**) was written separately and has never been used for training, fitting or threshold choice.
  Disclosure: after the first full evaluation the rule set was refined once (a bare "congratulations" no longer counts as a reward lure; three genuine-notice rules were added: delivery hand-over OTP, branch-visit KYC reminders, "do not click links" warnings). The refinements were chosen by reading the false alarms on the DEV set only - the locked messages were not inspected - but the aggregate locked numbers from the first run had been seen, so treat the locked test as *lightly* contaminated at the level of one tuning round. Locked-test results before the refinement: 84 % caught at 14.6 % false alarms (flag), 80 % at 4.2 % (block); after: see section 3. The change in block-level false alarms (2 -> 4 of 48 genuine messages) is within sampling noise.

**Fusion and thresholds.** Features are the wording-model logit, the (max) link-model logit, rule indicators and a has-link flag. Weights are fitted by L-BFGS-B with sign constraints (scam rules and
models >= 0, genuine-notice rules <= 0) and an L2 pull toward hand-set priors, so the fused model cannot learn that a scam keyword is "safe". Thresholds: dangerous = lowest score with <= 0.5 % false alarms,
suspicious = <= 3 % (weighted quantiles on fit data). Network thresholds are fixed at 0.5 / 0.9 on the calibrated attack probability.

**Metrics.** Recall, false-alarm rate, precision, AUC, each with a Wilson 95 % interval; and *precision at a 1 % scam prevalence* (a realistic inbox), because precision on a roughly 50/50 test set overstates real-world usefulness.
At 1 % prevalence: on the public held-out split ({{A_fpr}} false alarms) precision is {{A_prec1}}; on the harder locked hand-written test ({{D_fpr}} false alarms) it falls to {{D_prec1}} at the flag level and {{D_block_prec1}} at the block level.
That gap is the central open problem of this project - a real inbox sits somewhere between those two sets - and is why the UI treats SUSPICIOUS as a soft warning, only DANGEROUS blocks, and why the roadmap starts with real consented inbox data.
