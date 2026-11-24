# 4. Evidence JSON, grounded advisor and privacy

**Evidence record (`kavach.evidence/1.0`, schema in `schemas/evidence.schema.json`).** Verdict (band, risk, confidence, thresholds), category, ranked signed signals (model and rule contributions with
plain-language descriptions), extracted entities (hosts, registered domains, flow statistics), a closed catalogue of remediation action ids (English/Hindi), and a privacy block
(`processed_on_device: true`, `network_calls: 0`, `raw_text_included: false`, rule snippets capped at 40 characters). The test-suite validates every evidence type against the schema and asserts the
message sentence is never copied into the record.

**On-device Llama advisor (built and measured on the phone).** The Android app (`android/`) runs the whole chain on the Vivo V40e with no network permission:

1. *Detector, unchanged.* The app embeds Python with Chaquopy (Python 3.12, NumPy 1.26.2) and runs the same `kavach/` package that produced every number in section 3. On 292 development
   messages and links, phone and laptop (NumPy 2.2.6) gave identical verdicts, categories and risk scores.
2. *Verdict first.* Risk fusion decides the band; the screen shows it before the language model starts. The model never sets or changes the verdict.
3. *Llama explains.* Llama 3.2 1B Instruct (SpinQuant INT4 export from `executorch-community`, about 1.1 GB, pushed with adb, not in the APK) runs through ExecuTorch (`executorch-android` 1.1.0,
   XNNPACK on the CPU), temperature 0, at most 96 new tokens. Its prompt, `advisor.build_explain_prompt`, contains only detector facts (verdict, risk, confidence, scam type, the top reasons,
   flagged domains) - never the message text - and asks for 2-3 sentences whose stance follows the verdict ("very likely" / "may be" / "no warning signs").
4. *Steps come from the playbook, not the model.* The action steps on screen are the remediation catalogue entries, word for word.
5. *Output checks, then fallback.* `kavach_bridge.finalize` shows Llama's text only if it passes all checks: no phone number or link absent from the evidence; no sentence sending the user to a
   link or number; no contradiction of the verdict; no certainty claims ("100 %", "definitely", a flat "this is a scam"; "likely" for a *suspicious* verdict); no claim that the user has already
   been harmed; and no mention of OTP/PIN, phone calls, payments or app installs unless a detector signal supports it. Otherwise the screen shows the deterministic template with the same shape.

*Why the prompt is narrow.* The first version gave Llama the wider `build_prompt` (facts plus the allowed actions). On the phone it turned the action "Do not call back the number in the message"
into the claim "the message asks you to call a number" - for a message with no number - and said the message asked for a PIN/CVV when no signal said so. Those outputs are now test cases.

*Measured on the phone* (section 5.4): first token after {{llm_ttft}} ms, {{llm_tps}} tokens/s while writing, {{llm_total}} ms for the whole explanation, peak app memory {{llm_rss}} MB;
Llama's text passed the checks for {{llm_shown}} of {{llm_samples}} scam messages per run.

**Prompt injection.** {{inj_n}} synthetic attack messages (`data/build_injection_set.py`): instruction overrides in English, Hindi and Hinglish, fake Llama chat tokens, fake facts JSON,
"verified by RBI" claims, a planted helpline and link, role-play, zero-width characters, benign padding, and a false-alarm attempt on a genuine OTP. Results (`scripts/eval_injection.py`,
`tests/test_prompt_injection.py`):
* attacks that **lowered** the detector's verdict: **{{inj_lowered}}**; attacks whose text reached the Llama prompt: **{{inj_leaks}}**;
* attacks that **raised** the verdict: {{inj_raised}} (the added "verified" claims and planted numbers/links look like scam wording themselves; recorded, not tuned away);
* on the phone, verdicts matched the laptop for {{inj_phone_equal}} of {{inj_n}}; Llama never repeated a planted number or link and never called a scam safe; with the final checks
  {{inj_llama}} explanations were shown and {{inj_template}} fell back to the template (three "you have been scammed" claims caught, two harmless texts rejected by over-strict checks).

The checks are pattern-based. They fail towards the template, but they cannot prove that every sentence is supported by the evidence; a measured faithfulness rate on a labelled set of Llama
outputs is roadmap work (section 7).

**Privacy.** No networking module is imported anywhere in `kavach/` (enforced by a test). Section 4.1 reproduces the automated offline proof.
