# 7. Limitations and roadmap

**Stated plainly.**
* *Hand-written benchmarks are small* ({{D_npos}}+{{D_nneg}} locked messages) and written by the team; intervals are wide. They are an out-of-distribution sanity check, not a population estimate.
  The locked test shows {{D_fpr}} false alarms at the flag level - too high for a blocking decision, which is why only the DANGEROUS band blocks ({{D_block_fpr}}).
* *Synthetic genuine messages* are templated; real inboxes are messier. The composite message+URL test set is constructed, not observed.
* *URL host model alone* is modest (AUC {{url_E_auc}} on held-out hosts); rules and the trusted-domain list carry much of the precision. Newly registered hosts on clean-looking domains will be missed.
* *Network model*: NSL-KDD is 1999-style data; R2L/U2R recall is near zero ({{net_r2l}}/{{net_u2r}}); the pcap tests are synthetic fixtures, not live traffic. It is a reconnaissance/flood detector, not an IDS replacement.
* *Language*: wording model and rules are English/Hinglish; Explanations are available in Hindi (Devanagari), but detection has not been validated on Devanagari or other Indian-language scams.
* *Phone measurements have a protocol deviation*: the {{arm_runs}} benchmark runs in section 5 were taken with airplane mode **off** (the phone was tethering the development laptop) and on USB power.
  The 30-minute battery/temperature run, the phone-level offline proof in airplane mode and the user study are still pending; nothing in this report estimates them.
* *App memory*: detector RSS on the phone is {{arm_rss}} MB because it is the whole Android app process (runtime + embedded Python); PSS is {{arm_pss}} MB. With Llama loaded the app peaks at about
  {{llm_rss}} MB, which is a real constraint on 4-6 GB phones.
* *Llama explanations*: a 1B model at INT4 follows instructions loosely (it sometimes gives advice or repeats a sentence); the output checks are pattern-based, catch the failure types seen so far,
  and also reject some harmless text. Faithfulness has not been measured on a labelled set.
* *Detector miss seen during the injection tests*: a plain "it's me on a friend's phone, send money urgently" message is rated safe (risk 0.03). It was not tuned away.

**Roadmap.** Collect real consented inbox samples for calibration; add Devanagari/regional-language detection; port the 40-line tree runtime and the 1 MB linear model to Kotlin (formats are flat arrays)
to drop the embedded Python and its memory; a labelled faithfulness evaluation of Llama's explanations and claim-level (not pattern) checking; incremental on-device threshold adaptation under a
false-alarm budget; a QUIC/TLS-aware network feature set replacing NSL-KDD.
