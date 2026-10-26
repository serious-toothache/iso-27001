# Scope Memo: Tausi Telehealth ISO/IEC 27001:2022 Readiness

| | |
|---|---|
| **Client** | Tausi Telehealth Ltd, Nairobi (fictional) |
| **Engagement** | ISO/IEC 27001:2022 readiness assessment, with a SOC 2 crosswalk (the insurer's procurement team accepts either) |
| **Fieldwork** | 13–23 October 2026 |
| **Operating-effectiveness look-back** | 1 July – 30 September 2026 (Q3) |
| **Prepared by** | Louisz Rigensky W. |

## 1. ISMS scope statement (proposed, for management approval)

> The ISMS covers the design, development, operation and support of the Tausi telehealth platform (patient mobile app, clinician web portal and API) hosted on Amazon Web Services, the source code and pipeline in GitHub, and the Nairobi-based staff and contractors who build and run it.

Interfaces at the boundary: patients and clinicians (users), the video-consultation and SMS suppliers (GAP-12), and the regional insurer (customer).

## 2. Cloud boundary

| Environment | ID | In scope | Why |
|---|---|---|---|
| AWS production account | `111122223333` | ✅ | Hosts all patient data |
| AWS dev/staging account | `444455556666` | ❌ (provisional) | Management states it holds only synthetic data. **Request R13** to confirm, because one orphan restore test ([WP-05](../05-iac-audit/workpaper-WP-05-s3-module.md)) shows production data does get copied around |
| GitHub org `tausi`, repo `tausi-platform` | | ✅ | App code, Terraform and the deploy pipeline (change management) |

## 3. Regions

| Region | Use | Data residency check |
|---|---|---|
| af-south-1 (Cape Town) | Primary production | Patient data stored here per the privacy notice |
| eu-west-1 (Ireland) | DR backups and restore tests | **Cross-border transfer of health data.** Management must show a documented transfer basis under the Kenya Data Protection Act 2019. Not tested here; raised as request R14 |

**Any regional service must be tested in both regions.** What's true in af-south-1 says nothing about eu-west-1. This is why the evidence collector v2 now loops over regions, and why it found EBS default encryption off in eu-west-1 (GAP-19).

## 4. Services: regional or global?

| Category | Services in use | Scope | Tested in |
|---|---|---|---|
| Identity | IAM, IAM password policy, root user | Global | [02](../02-evidence-collection) IAM-01 to IAM-04 |
| Monitoring | CloudTrail trail definitions | Global (trail can be multi-region) | 02 LOG-01 |
| Monitoring | AWS Config, GuardDuty | **Regional** | [07](../07-continuous-monitoring), 02 MON-01 |
| Storage | S3 buckets (Block Public Access is account-level) | Buckets regional, BPA global | [05](../05-iac-audit), 02 S3-01 |
| Compute | EC2, EBS encryption by default | **Regional** | 02 CRY-01 |
| Networking | VPCs, security groups | **Regional** | 02 NET-01, 07 |
| Database | RDS PostgreSQL (`patient-db`) | Regional | Network rule only (NET-01). Encryption deferred to a later engagement |

## 5. Shared responsibility and carve-outs

| Provider | Provider secures | Tausi secures (tested) | Carve-out evidence |
|---|---|---|---|
| AWS (IaaS/PaaS) | Facilities, hardware, hypervisor, managed-service internals | IAM, network rules, encryption settings, logging, OS on EC2, data | AWS SOC 2 Type II and ISO 27001 certificate via AWS Artifact (**R1**) |
| GitHub (SaaS) | Platform availability and security | Org settings, branch protection, members, workflows | GitHub SOC 2 Type II (**R2**) |
| Video and SMS suppliers | Their platforms | Supplier due diligence, contracts | None held. That is GAP-12 |

Provider-side controls aren't re-tested. Doing so would be over-testing.

## 6. Walkthrough and tooling

The production change walkthrough is recorded in [WP-06 §2](../06-pipeline-audit/workpaper-WP-06-change-management.md#2-walkthrough). Tooling found:

| Question | Answer |
|---|---|
| IaC? | Terraform. Standard module `s3-patient-data` for patient data ([05](../05-iac-audit)) |
| Pipeline platform? | GitHub Actions, `.github/workflows/deploy.yml` |
| Drift / CSPM? | AWS Config conformance pack (af-south-1 only). No third-party CSPM. Security Hub not enabled |
| Logs shipped where, kept how long, who has access? | CloudTrail to `tausi-cloudtrail-logs` (no Object Lock, see GAP-06). GitHub Actions logs kept 90 days and not exported (GAP-17). Access: Platform Lead and CTO |

## 7. Frameworks: test once, satisfy many

One collection and one test per control, mapped to both ISO 27001 Annex A and SOC 2 TSC in [`01-control-mapping`](../01-control-mapping/annex-a-control-mapping.csv). Every evidence envelope from the collector carries both `iso27001_2022_annex_a` and `soc2_tsc`.

## 8. Access arrangement

| Path | Use |
|---|---|
| Read-only IAM role `tausi-auditor-readonly` (AWS managed `SecurityAudit`, MFA required, 30-day expiry) plus CloudTrail Lake query access | Exploration and re-performance (the evidence collector, CloudTrail queries) |
| GitHub org "security manager" role (read-only) plus audit log export | Branch protection, PRs, audit log |
| Targeted exports by Platform Lead | Final evidence package (state files, Config history, Jira tickets) |

## 9. Independence and AI use

- AI (Claude Code with the `grc-auditor` plugin) is used to draft parts of the workpapers and to cross-check evidence. Every use is logged with prompt, output reference, human review and tool version in the [AI use log](../08-evidence-evaluation/ai-use-log.md).
- Shared-tool check: Tausi engineers do not use the same AI workspace, and no AI-generated output from the client is relied on as evidence.
- The auditor did not design, build or operate any control under review. The control narrative in [04](../04-control-narrative) describes a *target* design and is labelled as such.

## 10. People (roles referred to in workpapers)

| AWS user / GitHub login | Role |
|---|---|
| `amina.otieno` / `amina-otieno` | CTO, GitHub org admin |
| `david.mutua` / `david-mutua` | Head of Engineering |
| `brian.kamau` / `brian-kamau` | Platform Lead, GitHub org admin |
| `carol.wanjiru` / `carol-wanjiru` | Data Engineer |
| `contractor-devops` / `kip-devops` | External DevOps contractor |
| — / `faith-njeri`, `joseph-ouma` (+ `joseph-ouma-dev`) | Software engineers (no AWS console access) |
