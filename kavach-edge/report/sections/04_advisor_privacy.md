# 4. Evidence JSON, grounded advisor and privacy

**Evidence record (`kavach.evidence/1.0`, schema in `schemas/evidence.schema.json`).** Verdict (band, risk, confidence, thresholds), category, ranked signed signals (model and rule contributions with
plain-language descriptions), extracted entities (hosts, registered domains, flow statistics), a closed catalogue of remediation action ids (English/Hindi), and a privacy block
(`processed_on_device: true`, `network_calls: 0`, `raw_text_included: false`, rule snippets capped at 40 characters). The test-suite validates every evidence type against the schema and asserts the
message sentence is never copied into the record.

**Grounded advisor.** `kavach/advisor.py` builds a compact system+user prompt from the evidence (not from the message) and defines the output shape. A deterministic template explainer produces the same shape
and is what the demo and the user study use. The on-device LLM (Llama-family via ExecuTorch, required by the challenge) plugs in at one point: feed it `evidence["advisor_prompt"]`, then run
`advisor.check_grounding(text, evidence)`, which rejects any phone number or URL not present in the evidence or the remediation catalogue; on failure fall back to the template. The detector never depends on the LLM,
so a slow or unavailable model cannot weaken protection.

**Privacy.** No networking module is imported anywhere in `kavach/` (enforced by a test). Section 4.1 reproduces the automated offline proof.
