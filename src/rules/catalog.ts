// src/rules/catalog.ts

import { ruleRegistry, type RuleCatalogEntry } from "./registry.js";
import { OWASP_LLM_TOP10, OWASP_AGENTIC, MITRE_ATLAS, NIST_AI_RMF } from "../compliance.js";
// Import rule modules so registry rules are registered wherever the catalog is
// consumed (reports, tests, the generate-catalog script) — not only via Tool 1.
import "./iam-rules.js";
import "./bedrock-rules.js";

/** Metadata for Tool 2's detection-layer findings (not registry rules — they are
 * constructed inline in find-prompt-injection.ts). Cataloged here so every finding
 * ruleId has a uniform threat/rationale lookup. */
const DETECTION_RULE_METADATA: RuleCatalogEntry[] = [
  {
    ruleId: "prompt-injection-*",
    title: "Prompt injection signature detected",
    description: "An InvokeModel request body matched a known prompt-injection regex (ignore-previous-instructions, system-prompt-leak, roleplay-jailbreak, or token-smuggling).",
    threat: "An attacker or compromised upstream application is submitting crafted prompts to override instructions, leak the system prompt, jailbreak the model, or smuggle internal reasoning.",
    rationale: "CloudWatch Logs carries the actual prompt body; regex on the request catches the attack at the point of injection with the principal and event ID for response. This is the project's differentiator — no vendor ships post-hoc prompt-injection detection.",
    severity: "critical",
    appliesTo: "invocation_log",
    complianceFrameworks: [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_AGENTIC.ASI01_GOAL_HIJACK, MITRE_ATLAS],
  },
  {
    ruleId: "off-hours-bedrock-usage",
    title: "Off-hours Bedrock usage spike",
    description: "A principal made more than 3 Bedrock invocations during off-hours (UTC 22:00-06:00 or weekend).",
    threat: "Repeated model invocation outside business hours may indicate automated exfiltration, a compromised credential running batch extraction, or a misconfigured job.",
    rationale: "Time-based anomaly detection uses CloudTrail metadata that is always present; it surfaces behavioral signal even when prompt bodies are unavailable (logging off). UTC-biased but tunable.",
    severity: "medium",
    appliesTo: "cloudtrail_event",
    complianceFrameworks: [NIST_AI_RMF, MITRE_ATLAS],
  },
  {
    ruleId: "guardrail-less-invocation",
    title: "Bedrock invocations without a guardrail",
    description: "A principal made InvokeModel calls carrying no guardrailId.",
    threat: "The application invokes models without a guardrail, so no preventive content/PII/topic control applies at the Bedrock layer for those calls.",
    rationale: "Config-level guardrail audits (Tool 1) cannot see runtime attachment; this check fires at the invocation layer where attachment actually matters, closing the gap between 'a guardrail exists' and 'a guardrail was used.'",
    severity: "medium",
    appliesTo: "invocation_log",
    complianceFrameworks: [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, MITRE_ATLAS],
  },
  {
    ruleId: "cloudtrail-management-disabled",
    title: "CloudTrail management-event logging is not enabled",
    description: "No active CloudTrail trail was found in the region; metadata-based detection was skipped.",
    threat: "A missing CloudTrail produces a false 'no signals detected' clean bill; the user believes they have no Bedrock activity when in fact detection is non-functional.",
    rationale: "The honest output when CloudTrail is off is a NOT_APPLICABLE, not an empty result. This prevents the most embarrassing failure mode for a detection tool — reporting clean when it cannot see.",
    severity: "medium",
    appliesTo: "cloudtrail_config",
    complianceFrameworks: [NIST_AI_RMF, MITRE_ATLAS],
  },
  {
    ruleId: "excessive-token-usage",
    title: "High token count Bedrock invocation",
    description: "An invocation consumed more than the configured token threshold (default 100000).",
    threat: "A single invocation consuming an anomalously high token count may indicate data exfiltration via large model responses (extracted context, retrieved documents).",
    rationale: "Uses the real consumed totalTokenCount from invocation-log metadata, not the caller's maxTokens cap. Complements signature-based detection for novel exfiltration that does not match known injection patterns.",
    severity: "low",
    appliesTo: "invocation_log",
    complianceFrameworks: [OWASP_LLM_TOP10.LLM10_UNBOUNDED_CONSUMPTION, NIST_AI_RMF],
  },
  {
    ruleId: "prompt-scan-logging-unavailable",
    title: "Prompt content scan skipped",
    description: "Model-invocation logging is disabled or S3-only; the content scan could not run.",
    threat: "Content scanning cannot run because model-invocation logging is disabled or S3-only; prompt-injection detection is non-functional.",
    rationale: "Surfaces the dependency explicitly rather than returning an empty result. Makes bedrock-logging-disabled a load-bearing finding, not hygiene.",
    severity: "medium",
    appliesTo: "bedrock_config",
    complianceFrameworks: [NIST_AI_RMF, MITRE_ATLAS],
  },
];

/** All rule catalog entries: registry rules + detection rules. */
export function allRuleMetadata(): RuleCatalogEntry[] {
  return [...ruleRegistry.catalog(), ...DETECTION_RULE_METADATA];
}

/** Lookup metadata for a finding's ruleId. Returns undefined for unknown ruleIds.
 *  Supports wildcard entries (ruleId ending in '-') for signature variants like
 *  prompt-injection-ignore-previous-instructions. */
export function getRuleMetadata(ruleId: string): RuleCatalogEntry | undefined {
  const all = allRuleMetadata();
  const exact = all.find(r => r.ruleId === ruleId);
  if (exact) return exact;
  return all.find(r => r.ruleId.endsWith("-*") && ruleId.startsWith(r.ruleId.slice(0, -1)));
}
