# 7. Limitations and roadmap

**Stated plainly.**
* *Hand-written benchmarks are small* ({{D_npos}}+{{D_nneg}} locked messages) and written by the team; intervals are wide. They are an out-of-distribution sanity check, not a population estimate.
  The locked test shows {{D_fpr}} false alarms at the flag level - too high for a blocking decision, which is why only the DANGEROUS band blocks ({{D_block_fpr}}).
* *Synthetic genuine messages* are templated; real inboxes are messier. The composite message+URL test set is constructed, not observed.
* *URL host model alone* is modest (AUC {{url_E_auc}} on held-out hosts); rules and the trusted-domain list carry much of the precision. Newly registered hosts on clean-looking domains will be missed.
* *Network model*: NSL-KDD is 1999-style data; R2L/U2R recall is near zero ({{net_r2l}}/{{net_u2r}}); the pcap tests are synthetic fixtures, not live traffic. It is a reconnaissance/flood detector, not an IDS replacement.
* *Language*: wording model and rules are English/Hinglish; Explanations are available in Hindi (Devanagari), but detection has not been validated on Devanagari or other Indian-language scams.
* *Arm measurements, user study and the LLM advisor timing are pending on-device runs* (sections 5 and 6 list the exact commands). Nothing in this report estimates them.

**Roadmap.** Collect real consented inbox samples for calibration; add Devanagari/regional-language detection; port the 40-line tree runtime and the 1 MB linear model to Kotlin (formats are flat arrays);
on-device LLM explainer with ExecuTorch and a measured grounding-failure rate; incremental on-device threshold adaptation under a false-alarm budget; a QUIC/TLS-aware network feature set replacing NSL-KDD.
