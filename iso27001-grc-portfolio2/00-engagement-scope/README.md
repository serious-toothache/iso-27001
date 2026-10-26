# 00 · Engagement Scope: Draw the Cloud Boundary Before Testing Anything

**CGE-AUD Domain 1: Cloud and code literacy** and **Domain 7.2: ISO 27001 in cloud-native environments** · **Files:** [`scope-memo.md`](scope-memo.md) · [`evidence-request-list.md`](evidence-request-list.md)

## What I built

The two documents an engagement starts with:

- **[Scope memo](scope-memo.md):** ISMS scope statement, accounts and regions in scope, which services are regional or global, the shared-responsibility carve-outs, tooling found in the walkthrough, the multi-framework plan, the access arrangement, and the independence and AI-use declaration.
- **[Evidence request list](evidence-request-list.md):** 16 requests, each written as the *right ask* (module + state + pipeline, not "25 screenshots"), with status and where each one is used.

## Why it matters

**Scope decides what the tests can prove.** Marking EC2, Config and GuardDuty as *regional* is what made the collector check eu-west-1. That surfaced a DR region outside the baseline (GAP-19) that a single-region run would have reported as clean.

**Carve out, don't over-test.** AWS and GitHub cover their side with their own SOC 2 reports. The tests here cover only what Tausi configures.

**The ask signals competence.** "Send me the module, the state file and the pipeline" gets a different response from an engineering team than "send me screenshots". The request list also records what *couldn't* be produced, which is evidence too (R8, R10, R11, R15).
