# User study protocol - "Can ordinary people understand and act on Kavach-Edge warnings?"

**Question.** Does a plain-language explanation (headline + why + what to do) help people make the right decision about a suspicious message,
compared with the raw technical evidence a detector without an explanation layer would expose?
**Design.** Within-subject, counterbalanced. Each participant sees the same 10 messages (6 scams, 4 genuine; written for the study, drawn from the
DEV benchmark with a fixed seed). For each message the system output is shown either as **A: raw evidence** or **B: plain-language explanation**; which
messages get which condition alternates by participant number, and presentation order is a seeded shuffle of the participant number.
**Target n.** 12-15 (minimum 8). Recruit people who are *not* on the team: classmates from other branches, family members, hostel staff - mixed ages if you can,
including at least 3 people over 40 (they are the actual scam targets). 18+ only.
**Time.** ~12 min per person. **No incentives needed;** offer chai.

## Materials (all in this folder)
* `study_app.html` - self-contained, works offline, runs on a laptop or phone browser. Built by `build_scenarios.py` from real pipeline output.
* `CONSENT_AND_DEBRIEF.md` - the consent wording (also shown in the app) and a spoken debrief.
* `analyze_study.py` - scoring and statistics.

## Procedure (per participant)
1. Give the participant number (1, 2, 3, ...). **Use each number once** - the number decides the counterbalancing. Participants 1..N alternate A/B assignment.
2. Open `study_app.html` (double-click on a laptop; on a phone, copy it over and open in Chrome). Read the consent screen aloud if asked. Do not coach during trials.
3. Sit next to them; say only: "Answer as you would on your own phone. If unsure, pick what you'd really do." Note any spontaneous remarks.
4. At the end tap **Download my results (CSV)**; save as `study/data/P<NN>.csv`. (If download is blocked on a phone, tap *Copy CSV* and paste into a file.)
5. Spoken debrief (see consent file). Ask one open question: "What was the most confusing part?" and write it on a card.

## Measures
| Measure | How | Why |
|---|---|---|
| Action correctness | pick one of 5 actions per message; correct = ignore for scams, "genuine" for legit | does the warning change behaviour correctly? |
| Comprehension | "what kind of message is this?" 4 options | do they understand the threat type? |
| Confidence, Trust | 1-5 scales per message | calibration: trust should not be blind |
| Time | per message, ms | cognitive load |
| SUS | standard 10 items, once at the end | overall usability, comparable to published benchmarks |

## Analysis plan (fixed before collecting data)
Paired B - A per participant on each measure: mean difference with a 10,000-resample bootstrap 95 % CI, paired t-test, Wilcoxon signed-rank, Cohen's dz.
SUS reported with CI against the 68 benchmark. Error cases (where the detector was wrong - 2 of 10 scenarios) are examined separately: do people over-trust a wrong verdict?
No participant is excluded except for incomplete sessions; exclusions are listed. Report whatever comes out, including null results.

```bash
python3 study/analyze_study.py --report        # reads study/data/*.csv, writes results/STUDY_RESULTS.md
python3 study/analyze_study.py --report --allow-small   # pilot with <5 people (labelled PILOT)
```
`analyze_study.py` refuses test data (synthetic=1) so bot runs can never be reported as results.

## Ethics and privacy
No names, numbers or real messages are collected; participant number only. All text is fictional. Data stays on the device until you copy it. Participation is voluntary
and can stop at any time. Do not use minors. Keep CSVs out of the public repo if participants asked for that (the repo ignores `study/data/` by default).

## Limitations to state in the report
Small convenience sample; fictional messages; lab setting (no real money at stake); explanation B is the deterministic template that mirrors the LLM's output format,
not the free-form Llama text itself; two of the ten scenarios are ones the detector got wrong, by design of an unfiltered sample.
