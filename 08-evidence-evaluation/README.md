# 08 · Evidence Evaluation: Judging What You Receive

**CGE-AUD Domain 6: Evidence evaluation** and **Domain 5.5: AI guardrails** · **Files:** [`evidence-quality-assessment.md`](evidence-quality-assessment.md) · [`sampling-rationale.md`](sampling-rationale.md) · [`workpaper-WP-08-A.8.5-mfa.md`](workpaper-WP-08-A.8.5-mfa.md) · [`ai-use-log.md`](ai-use-log.md)

## What I built

The other folders collect evidence and run tests. This one makes the work **defensible**:

| File | What it answers |
|---|---|
| [Evidence quality assessment](evidence-quality-assessment.md) | Is each artifact relevant, reliable, sufficient and timely? Where does it sit in the evidence hierarchy? Was the evidence generator itself working the whole period? |
| [Sampling rationale](sampling-rationale.md) | For every test: which strategy (entire population, n = 1 module, entity, event-type, anomaly, temporal), which slice, what size, and why |
| [WP-08: A.8.5 MFA](workpaper-WP-08-A.8.5-mfa.md) | A worked example of the modern workpaper: precise population, 100% re-performance, period-wide evidence, hashes, and no "evidence provided by management" |
| [AI use log](ai-use-log.md) | The prompt, output, human review and tool version for every AI-assisted step, plus the criteria for rejecting AI output |

## Why it matters

**Evidence quality is a test, not an assumption.** CloudTrail is a system log, but with log file validation off it can't be proven untampered. So it sits at tier 2, and every finding that relies on it is corroborated by a second source.

**Check the meta-controls.** The Config recorder was off for 6 days, build logs expired after 90 days, and branch protection was weakened for 3½ hours. Each of these limits what the *other* evidence can prove, so each is recorded before any conclusion.

**Write the sampling down.** "We tested the module once" is rejected in review. The same sentence with the n = 1 rationale passes.

**AI drafts, the auditor signs.** The log leaves the human-review boxes empty until the author has actually done the review. Ticking them in advance would defeat the point.
