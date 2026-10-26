# AI Use Log

**AI assists. The auditor signs.** Claude was used to read evidence, draft workpaper text and write the test scripts. It did not decide scope, reach conclusions, set ratings or sign anything. This log records what a reviewer needs to reproduce or challenge that work: the prompt, the output, the human review, and the tool version.

## Tool

| | |
|---|---|
| Tool | Claude Code (CLI), model `claude-opus-5-5` |
| Plugins available | `grc-auditor` (review-evidence, generate-workpaper, finding-generator), `aws-inspector`, `github-inspector` |
| Date | 26 October 2026 |
| Data shared | Only the fictional Tausi evidence in this repository. No real client data |

## Log

The **Human review** column is for the author to complete. Each line is signed only after the output has been checked against the source evidence using the rejection criteria below.

| ID | Used for | Prompt (structured) | Output | Human review |
|---|---|---|---|---|
| AI-01 | Align the portfolio with the CGE-AUD course notes | "Align GRC Engineer Academy – Auditor with iso27001-grc-portfolio. Create a separate copy named iso27001-grc-portfolio2." | This repository version, mapped in [`ALIGNMENT.md`](../ALIGNMENT.md) | ☐ Read every artifact against the course notes |
| AI-02 | SOC 2 crosswalk for the 18 Annex A rows | Propose a SOC 2 TSC for each Annex A row, based on the implementation and evidence columns | `soc2_tsc` column in [`annex-a-control-mapping.csv`](../01-control-mapping/annex-a-control-mapping.csv) | ☐ Each mapping checked against the TSC points of focus |
| AI-03 | WP-05 module read | Read the module in README → main.tf → variables.tf → validation → outputs order, cite file:line for each control attribute, flag any control exposed as a variable | [WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md), [`iac_audit.py`](../05-iac-audit/iac_audit.py) | ☐ Every line citation opened and checked |
| AI-04 | WP-06 SoD tests | Test every merged PR and deploy for human approval, author ≠ approver as people, overrides, weakened-protection windows, workflow changes, and the three-link trace | [WP-06](../06-pipeline-audit/workpaper-WP-06-change-management.md), [`sod_checks.py`](../06-pipeline-audit/sod_checks.py) | ☐ PRs #241, #248, #255, #258, #262, #264 checked by hand against the CSVs |
| AI-05 | WP-07 continuous controls | Find execution gaps, drift chain breakpoints, MTTR vs SLA, and the 5 Ws for monitoring changes | [WP-07](../07-continuous-monitoring/workpaper-WP-07-continuous-controls.md), [`analyze_continuous.py`](../07-continuous-monitoring/analyze_continuous.py) | ☐ 3 sampled days re-performed by hand |
| AI-06 | WP-08 and gap register | Draft the WP-08 workpaper. Propose likelihood × impact for GAP-13 to GAP-19 | [WP-08](workpaper-WP-08-A.8.5-mfa.md), [`gap-register.csv`](../03-gap-assessment/gap-register.csv) | ☐ Every rating challenged. Business context added |

## Rejection criteria applied to every output

Reject, refine the prompt and re-run if the output:

- [ ] states a conclusion with no citation to the underlying evidence file
- [ ] states something that doesn't match the source data on spot-check
- [ ] reads like the auditor's signed opinion rather than a draft for review
- [ ] leaves out control language the framework requires (Annex A control number and requirement, SOC 2 criterion)

## Independence

- AI use is disclosed in the [scope memo](../00-engagement-scope/scope-memo.md#9-independence-and-ai-use) and in the header of every workpaper.
- The scripts are deterministic and run without AI. A reviewer can re-run every test and get the same result without trusting the model.
