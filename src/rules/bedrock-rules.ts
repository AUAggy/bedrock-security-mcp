// src/rules/bedrock-rules.ts

import { ruleRegistry, type RuleSpec } from "./registry.js";
import { OWASP_LLM_TOP10, OWASP_AGENTIC, NIST_AI_RMF, AWS_WA_ML_LENS, MITRE_ATLAS } from "../compliance.js";
import type { BedrockSecurityFinding } from "../types.js";

// Local helper mirroring iam-rules.ts. Kept duplicated to avoid a shared-module
// refactor in the MVP; the shape is stable.
function finding(
  spec: Pick<RuleSpec, "ruleId" | "title" | "severity" | "complianceFrameworks">,
  overrides: Partial<BedrockSecurityFinding>
): BedrockSecurityFinding {
  return {
    findingId: `${spec.ruleId}-${overrides.resource ?? "unknown"}`,
    ruleId: spec.ruleId,
    title: spec.title,
    severity: spec.severity,
    status: "FAIL",
    resource: overrides.resource ?? "unknown",
    region: overrides.region ?? "unknown",
    details: overrides.details ?? "",
    remediation: overrides.remediation ?? "",
    complianceFrameworks: overrides.complianceFrameworks ?? spec.complianceFrameworks,
    reference: overrides.reference,
  };
}

// ── Rule: bedrock-logging-disabled ─────────────────────────────
ruleRegistry.register({
  ruleId: "bedrock-logging-disabled",
  title: "Bedrock model-invocation logging is disabled",
  description: "Model-invocation logging (prompts and responses) is not enabled. Without logging, there is no audit trail for prompt injection incidents or data exfiltration via LLMs, and Tool 2's content scan cannot run.",
  threat: "Without model-invocation logging, prompt-injection incidents and data exfiltration via LLM responses leave no audit trail. Tool 2's content scan also cannot run.",
  rationale: "Logging is the precondition for every detection control in this tool. A security program that cannot reconstruct what a compromised model endpoint did is blind to its primary AI incident classes (MITRE ATLAS).",
  severity: "high",
  appliesTo: "bedrock_config",
  complianceFrameworks: [AWS_WA_ML_LENS.SEC_10, NIST_AI_RMF, MITRE_ATLAS],
  check(item: Record<string, unknown>) {
    if (item.loggingEnabled as boolean) return null;
    return finding(
      {
        ruleId: "bedrock-logging-disabled",
        title: "Bedrock model-invocation logging disabled",
        severity: "high",
        complianceFrameworks: [AWS_WA_ML_LENS.SEC_10, NIST_AI_RMF, MITRE_ATLAS],
      },
      {
        resource: "bedrock:model-invocation-logging",
        region: (item.region as string) ?? "global",
        details: "Model-invocation logging is not enabled. Prompts and responses are not logged to CloudWatch or S3. This eliminates the audit trail needed for prompt-injection investigation AND disables Tool 2's content scan (which reads prompt bodies from CloudWatch Logs).",
        remediation: "Enable model-invocation logging via AWS Console (Bedrock → Settings → Model invocation logging) or CloudFormation. Configure a CloudWatch Logs destination (required for Tool 2 content scanning) with a customer-managed KMS key.",
        reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
      }
    );
  },
});

// ── Rule: invocation-logs-without-cmk ──────────────────────────
// CloudWatch Logs are SSE-CloudWatch encrypted by default. A customer-managed
// CMK gives the customer key rotation + revoke access independently of AWS.
ruleRegistry.register({
  ruleId: "invocation-logs-without-cmk",
  title: "Bedrock invocation logs lack customer-managed KMS encryption",
  description: "The CloudWatch log group receiving Bedrock model-invocation logs uses default SSE-CloudWatch encryption, not a customer-managed KMS key. Prompt bodies live in these logs.",
  threat: "Prompt bodies and model responses in the log group are protected only by default CloudWatch encryption; you cannot independently revoke or rotate access.",
  rationale: "Prompt logs are sensitive (they may carry PII, proprietary context, or extracted training data). A customer-managed CMK gives incident-response and key-revocation independence from the service, satisfying AWS WA ML SEC-6.",
  severity: "medium",
  appliesTo: "bedrock_config",
  complianceFrameworks: [AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const kmsKeyId = item.kmsKeyId as string | undefined;
    const logGroupName = item.logGroupName as string;
    // The rule only applies when a CloudWatch destination is configured.
    if (!logGroupName) return null;
    if (kmsKeyId) return null; // CMK present
    return finding(
      {
        ruleId: "invocation-logs-without-cmk",
        title: "Invocation log group lacks customer-managed KMS key",
        severity: "medium",
        complianceFrameworks: [AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
      },
      {
        resource: `arn:aws:logs:::log-group:${logGroupName}`,
        region: (item.region as string) ?? "global",
        details: `Invocation log group '${logGroupName}' uses default CloudWatch encryption. Prompt bodies and model responses in this log group are not protected by a customer-managed KMS key, so you cannot independently revoke access or rotate the key.`,
        remediation: "Associate a customer-managed KMS key with the CloudWatch log group (logs:AssociateKmsKey) and grant only the Bedrock logging role + incident-response roles decrypt access. Update the Bedrock model-invocation logging role to allow kms:GenerateDataKey* on the key.",
        reference: "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
      }
    );
  },
});

// ── Rule: guardrail-content-filter-weak ────────────────────────
ruleRegistry.register({
  ruleId: "guardrail-content-filter-weak",
  title: "Guardrail lacks prompt-attack filter or runs at low strength",
  description: "A Bedrock Guardrail exists but either has no PROMPT_ATTACK content filter or runs content filters below HIGH strength. This is the primary preventive control for the prompt-injection attacks Tool 2 detects.",
  threat: "Prompt-injection and harmful-content attacks reach the model unfiltered; the guardrail is the last preventive layer before model invocation.",
  rationale: "This is the preventive counterpart to Tool 2's prompt-injection detection. A guardrail without a HIGH-strength PROMPT_ATTACK filter is theatre: it exists but does not block the attack class it is named for.",
  severity: "high",
  appliesTo: "bedrock_guardrail",
  complianceFrameworks: [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const cfg = item.config as { hasPromptAttackFilter: boolean; minContentStrength: string; name: string; guardrailArn: string };
    if (cfg.hasPromptAttackFilter && cfg.minContentStrength === "HIGH") return null;
    return finding(
      {
        ruleId: "guardrail-content-filter-weak",
        title: `Guardrail '${cfg.name}' has weak content filtering`,
        severity: "high",
        complianceFrameworks: [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
      },
      {
        resource: cfg.guardrailArn,
        region: (item.region as string) ?? "global",
        details: `Guardrail '${cfg.name}' ${cfg.hasPromptAttackFilter ? "has a PROMPT_ATTACK filter" : "has NO PROMPT_ATTACK filter"}, with minimum content-filter strength '${cfg.minContentStrength}'. Tool 2 flags prompt-injection signatures in your invocation logs; this guardrail is the preventive counterpart and is currently too weak to block them.`,
        remediation: "Edit the guardrail: enable the PROMPT_ATTACK filter and set all content filters (sexual, violence, hate, insults, misconduct, prompt_attack) to HIGH for both input and output.",
        reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
      }
    );
  },
});

// ── Rule: guardrail-no-pii-filter ──────────────────────────────
ruleRegistry.register({
  ruleId: "guardrail-no-pii-filter",
  title: "Guardrail has no PII filter configured",
  description: "The guardrail does not configure any PII entity filters. Prompts and responses can carry PII (SSN, email, phone) without being masked or blocked.",
  threat: "Prompts and responses can carry PII (SSN, email, phone) unmasked, leaking it into logs, downstream stores, or model training corpora.",
  rationale: "PII filtering at the guardrail layer is content-aware in a way IAM and network controls are not. Without it, the data-protection story for the workload is incomplete regardless of encryption.",
  severity: "medium",
  appliesTo: "bedrock_guardrail",
  complianceFrameworks: [OWASP_LLM_TOP10.LLM02_SENSITIVE_INFO, AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const cfg = item.config as { piiEntityCount: number; name: string; guardrailArn: string };
    if (cfg.piiEntityCount > 0) return null;
    return finding(
      {
        ruleId: "guardrail-no-pii-filter",
        title: `Guardrail '${cfg.name}' has no PII filter`,
        severity: "medium",
        complianceFrameworks: [OWASP_LLM_TOP10.LLM02_SENSITIVE_INFO, AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
      },
      {
        resource: cfg.guardrailArn,
        region: (item.region as string) ?? "global",
        details: `Guardrail '${cfg.name}' has ${cfg.piiEntityCount} PII entities configured. Prompts/responses can carry PII without masking.`,
        remediation: "Add PII entity filters to the guardrail (at minimum: SSN, EMAIL, PHONE, CREDIT_DEBIT_NUMBER). Configure as MASK or BLOCK per your data-handling policy.",
        reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-pii.html",
      }
    );
  },
});

// ── Rule: guardrail-no-denied-topics ───────────────────────────
ruleRegistry.register({
  ruleId: "guardrail-no-denied-topics",
  title: "Guardrail blocks no topics",
  description: "The guardrail has an empty denied-topics list. A guardrail that blocks nothing provides only content filtering, not topic scoping.",
  threat: "The guardrail blocks content categories but no topics; out-of-scope domains (legal, medical, financial advice) are not refused.",
  rationale: "Topic scoping bounds what the model will discuss, reducing misuse and liability. A guardrail with no topics is a content filter, not a scope control.",
  severity: "low",
  appliesTo: "bedrock_guardrail",
  complianceFrameworks: [OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const cfg = item.config as { deniedTopicCount: number; name: string; guardrailArn: string };
    if (cfg.deniedTopicCount > 0) return null;
    return finding(
      {
        ruleId: "guardrail-no-denied-topics",
        title: `Guardrail '${cfg.name}' blocks no topics`,
        severity: "low",
        complianceFrameworks: [OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
      },
      {
        resource: cfg.guardrailArn,
        region: (item.region as string) ?? "global",
        details: `Guardrail '${cfg.name}' has ${cfg.deniedTopicCount} denied topics. It provides content filtering but no topic scoping, so out-of-scope domains are not blocked.`,
        remediation: "Add denied-topic configurations for any domain outside this guardrail's intended use case (e.g., financial advice, legal guidance, internal HR topics).",
        reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
      }
    );
  },
});

// ── Rule: guardrail-grounding-disabled ─────────────────────────
ruleRegistry.register({
  ruleId: "guardrail-grounding-disabled",
  title: "Guardrail has no contextual grounding",
  description: "The guardrail does not configure contextual grounding. For RAG workloads, grounding reduces hallucinated answers and ungrounded exfiltration of retrieved context.",
  threat: "For RAG workloads, ungrounded or hallucinated responses are not blocked at the guardrail layer; the model can assert facts not present in retrieved context.",
  rationale: "Contextual grounding is the guardrail-native control for hallucination and ungrounded exfiltration of retrieved context (OWASP LLM08). Without it, RAG output quality and safety rely entirely on the application layer.",
  severity: "low",
  appliesTo: "bedrock_guardrail",
  complianceFrameworks: [OWASP_LLM_TOP10.LLM08_VECTOR_WEAKNESSES, AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const cfg = item.config as { hasGrounding: boolean; name: string; guardrailArn: string };
    if (cfg.hasGrounding) return null;
    return finding(
      {
        ruleId: "guardrail-grounding-disabled",
        title: `Guardrail '${cfg.name}' lacks contextual grounding`,
        severity: "low",
        complianceFrameworks: [OWASP_LLM_TOP10.LLM08_VECTOR_WEAKNESSES, AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
      },
      {
        resource: cfg.guardrailArn,
        region: (item.region as string) ?? "global",
        details: `Guardrail '${cfg.name}' has no contextual grounding filter. For RAG/KB-backed workloads, this means ungrounded or hallucinated responses are not blocked at the guardrail layer.`,
        remediation: "If this guardrail protects a RAG workload, add a contextual grounding filter with grounding and relevance thresholds (start at 0.75 and tune).",
        reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding.html",
      }
    );
  },
});
