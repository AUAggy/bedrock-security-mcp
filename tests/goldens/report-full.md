# AWS AI/ML Workload Security Posture Report

**Generated:** 2026-07-04 00:00:00 UTC
**Account:** 111122223333
**Region:** us-east-1
**Posture score:** 1/100 | **Violations:** 7 | **Errors:** 1

## Executive Summary

**Overall Risk Rating:** CRITICAL

Found **7 security violation(s)** across 3 categor(ies):

- **IAM & Access:** 3 issue(s)
- **Bedrock Configuration:** 2 issue(s)
- **Prompt Injection:** 2 issue(s)

> Address critical and high-severity findings within 24 hours. Medium findings within 7 days. Low findings during the next sprint.

## Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 2 |
| Medium   | 2 |
| Low      | 2 |

## Critical Findings

### RoleA has wildcard Bedrock permissions

- **Rule:** `wildcard-bedrock-action`
- **Resource:** `arn:aws:iam::111122223333:role/RoleA`
- **Compliance:** OWASP_LLM_TOP10:LLM06, NIST_AI_RMF

**Threat:** A compromised principal with bedrock:* can invoke any foundation model, extract training data via prompt extraction, poison knowledge bases, or create guardrails that selectively bypass content filters.

**Why it matters:** A Bedrock wildcard is worse than an S3 wildcard: model invocation is irreversible (data leaves the account in the response), and guardrail/KM manipulation weakens every other control. The blast radius is every Bedrock resource in the account, not one bucket.

Role has bedrock:* on *

**Remediation:**

Scope the actions.

[Reference](https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html)

---

### RoleD: trust policy allows wildcard principal

- **Rule:** `wildcard-principal`
- **Resource:** `arn:aws:iam::111122223333:role/RoleD`
- **Compliance:** OWASP_LLM_TOP10:LLM06, NIST_AI_RMF

**Threat:** Any AWS principal worldwide can assume this role and invoke models in your account. Cross-tenant and supply-chain actors can consume your model access at your cost and under your account identity.

**Why it matters:** Wildcard trust plus Bedrock permissions is the highest-impact IAM misconfiguration for AI workloads: it turns an IAM defect into a direct model-access path for arbitrary external identities. No region or IP condition rescues a Principal: * trust.

Role has bedrock:* on *

**Remediation:**

Scope the actions.

---

### Prompt injection signature detected: ignore-previous-instructions

- **Rule:** `prompt-injection-ignore-previous-instructions`
- **Resource:** `arn:aws:sts::111122223333:assumed-role/app/worker`
- **Compliance:** OWASP_LLM_TOP10:LLM06, NIST_AI_RMF

**Threat:** An attacker or compromised upstream application is submitting crafted prompts to override instructions, leak the system prompt, jailbreak the model, or smuggle internal reasoning.

**Why it matters:** CloudWatch Logs carries the actual prompt body; regex on the request catches the attack at the point of injection with the principal and event ID for response. This is the project's differentiator — no vendor ships post-hoc prompt-injection detection.

Request body contains "<script>" & special chars | pipes

**Remediation:**

Scope the actions.

---

## High Findings

### RoleA: Bedrock access has no condition keys

- **Rule:** `no-condition-keys` | **Compliance:** OWASP_LLM_TOP10:LLM06, NIST_AI_RMF

**Threat:** Bedrock access is usable from any IP, any region, at any time. A leaked long-term credential or a compromised SSRF path can invoke models from anywhere.

**Why it matters:** Condition keys are the only IAM-layer control that constrains where and when a permission is usable. Without them, geographic and time-based abuse patterns (off-hours exfiltration, unusual-region calls) are structurally unblockable at IAM.

Role has bedrock:* on *

**Fix:** Scope the actions.

### Bedrock model-invocation logging disabled

- **Rule:** `bedrock-logging-disabled` | **Compliance:** OWASP_LLM_TOP10:LLM06, NIST_AI_RMF

**Threat:** Without model-invocation logging, prompt-injection incidents and data exfiltration via LLM responses leave no audit trail. Tool 2's content scan also cannot run.

**Why it matters:** Logging is the precondition for every detection control in this tool. A security program that cannot reconstruct what a compromised model endpoint did is blind to its primary AI incident classes (MITRE ATLAS).

Role has bedrock:* on *

**Fix:** Scope the actions.

## Other Findings

| Severity | Rule | Resource | Summary |
|----------|------|----------|---------|
| medium | `guardrail-no-pii-filter` | `arn:aws:bedrock:us-east-1:111122223333:guardrail/g` | Guardrail 'Weak' has 0 PII entities \| prompts can carry PII unmasked |
| low | `excessive-token-usage` | `arn:aws:iam::111122223333:role/RoleA` | Role has bedrock:* on * |

## Remediation Roadmap

| Priority | Rule | Effort | Action |
|----------|------|--------|--------|
| CRITICAL | `wildcard-bedrock-action` | < 1 hour | RoleA has wildcard Bedrock permissions |
| CRITICAL | `wildcard-principal` | < 1 hour | RoleD: trust policy allows wildcard principal |
| HIGH | `no-condition-keys` | < 1 day | RoleA: Bedrock access has no condition keys |
| HIGH | `bedrock-logging-disabled` | < 1 day | Bedrock model-invocation logging disabled |
| MEDIUM | `guardrail-no-pii-filter` | < 1 week | Guardrail 'Weak' has no PII filter |
| CRITICAL | `prompt-injection-ignore-previous-instructions` | < 1 hour | Prompt injection signature detected: ignore-previous-instructions |
| LOW | `excessive-token-usage` | Next sprint | High token count Bedrock invocation: 150000 tokens |

## Compliance Mapping

| Framework | Violated Rules |
|-----------|----------------|
| NIST_AI_RMF | `wildcard-bedrock-action`, `wildcard-principal`, `no-condition-keys`, `bedrock-logging-disabled`, `guardrail-no-pii-filter`, `prompt-injection-ignore-previous-instructions`, `excessive-token-usage` |
| OWASP_LLM_TOP10:LLM06 | `wildcard-bedrock-action`, `wildcard-principal`, `no-condition-keys`, `bedrock-logging-disabled`, `guardrail-no-pii-filter`, `prompt-injection-ignore-previous-instructions`, `excessive-token-usage` |

## Posture Score

**1/100**

Score = 100 minus weighted violations (critical: 25, high: 10, medium: 3, low: 1). A clean account scores 100; a single critical finding caps the score at 75.

---

*Report generated by [bedrock-security-mcp](https://github.com/AUAggy/bedrock-security-mcp) — an opinionated MCP server for AWS AI/ML workload security.*

**Frameworks referenced:** OWASP LLM Top 10 (2025), OWASP Agentic Applications Top 10, NIST AI RMF, MITRE ATLAS