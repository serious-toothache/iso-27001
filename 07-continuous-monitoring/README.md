# 07 · Continuous Monitoring: Did the Control Run All Year, Not Just Today?

**CGE-AUD Domain 4: Cloud-native monitoring & continuous controls** · **Files:** [`workpaper-WP-07-continuous-controls.md`](workpaper-WP-07-continuous-controls.md) · [`analyze_continuous.py`](analyze_continuous.py) · [`evidence/`](evidence) · [`tests/`](tests)

## What I built

Tausi watches its configuration with AWS Config rules that page on-call when something drifts. A screenshot of a green dashboard taken today is the classic wrong evidence for that. This folder tests the control across the whole quarter, using the three-evidence stack:

| Layer | Evidence | Test |
|---|---|---|
| Configuration | [`config-recorder-status.json`](evidence/config-recorder-status.json) | Recorder in every region? Every rule routed to an alert? |
| Execution log | [`config-rule-evaluations-q3.csv`](evidence/config-rule-evaluations-q3.csv) | Any day in the period with no evaluation? |
| Alerts + resolution | [`drift-events-q3.csv`](evidence/drift-events-q3.csv) | Where did Detect → Alert → Ticket → Remediate → Validate break? MTTR vs SLA |
| Who did it | [`cloudtrail-sample-q3.json`](evidence/cloudtrail-sample-q3.json) | The 5 Ws for every event that changed the monitoring or caused drift |

## Run it

```bash
cd 07-continuous-monitoring
python analyze_continuous.py executions evidence/config-rule-evaluations-q3.csv --start 2026-07-01 --end 2026-09-30
python analyze_continuous.py drift evidence/drift-events-q3.csv --status evidence/config-recorder-status.json --as-of 2026-10-23
python analyze_continuous.py events evidence/cloudtrail-sample-q3.json --user contractor-devops
```

```
restricted-ssh                         ran 86/92 days  GAP 2026-08-14 to 2026-08-19 (6 days)
...
[broken response   ] DRF-02 mfa-enabled-for-iam-console-access carol.wanjiru | ticket - | open 113 days (SLA 7)
[broken alert      ] DRF-04 s3-bucket-versioning-enabled tausi-tmp-export-carol | ticket - | open 62 days (SLA 30)
[broken remediation] DRF-05 restricted-ssh sg-0a1b2c3d4e5f60002 (app-servers) | ticket TT-412 | open 50 days (SLA 7)
MTTR (remediated events): 21.4 h
Alert routing ignores rule: s3-bucket-versioning-enabled
No Config recorder in region: eu-west-1
```

Standard library only. Tests: `python -m pytest -q`.

## What it found

All three rules went dark on the same six days. CloudTrail shows `contractor-devops` stopped the recorder with a long-lived CLI key on 14 August, and nothing alerted. Of six drift events, only two were fixed. Every kind of breakpoint shows up once: an alert never sent, alerts never ticketed, a ticket left 43 days past SLA. The DR region has no recorder at all. → [GAP-18, GAP-19](../03-gap-assessment/README.md#4-findings)

## Why I built it this way

**Continuous controls change the sampling question.** You don't sample 25 days. You confirm there are **no gaps** across all of them, sample a handful of executions for output quality, and review **every** alert.

**Validate the evidence generator itself.** A Config rule can't report while its recorder is stopped. The 6-day gap is invisible on a dashboard that only shows the latest result. That's why the execution log is a separate layer of evidence.

**A good MTTR can hide a broken chain.** 21.4 hours sounds great, but it only counts the two events that were fixed. Reporting "2 of 6 resolved" next to MTTR keeps the metric honest.

**Find the breakpoint, not just the failure.** "Broken alert", "broken response" and "broken remediation" point to different owners (platform, on-call, the engineering team). The finding tells each one exactly what to fix.

## Limitations

- Three rules represent a conformance pack. The method is identical for 50.
- Drift events are a reconstruction joining Config timeline, EventBridge deliveries and Jira. A real engagement would request each source separately and join them the same way.
