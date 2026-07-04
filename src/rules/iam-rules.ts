// src/rules/iam-rules.ts

import { ruleRegistry, type RuleSpec } from "./registry.js";
import { OWASP_LLM_TOP10, OWASP_AGENTIC, NIST_AI_RMF, AWS_WA_ML_LENS } from "../compliance.js";
import type { AnalyzedStatement, BedrockSecurityFinding } from "../types.js";

// NOTE: each rule's registered `complianceFrameworks` is the canonical list used
// by the rule-engine error fallback. The `finding()` spec inside each check()
// re-states the same list — keep them in sync when editing.

/** Building block: create a finding from a rule violation */
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
    complianceFrameworks: spec.complianceFrameworks,
    reference: overrides.reference,
  };
}

// ── Rule: wildcard-bedrock-action ──────────────────────────────
ruleRegistry.register({
  ruleId: "wildcard-bedrock-action",
  title: "Role has wildcard bedrock:* permissions",
  description: "IAM role grants broad Bedrock actions via wildcard (bedrock:* or *). This allows invoking any model, creating guardrails, or modifying knowledge bases — a single compromised role could exfiltrate data or poison models.",
  threat: "A compromised principal with bedrock:* can invoke any foundation model, extract training data via prompt extraction, poison knowledge bases, or create guardrails that selectively bypass content filters.",
  rationale: "A Bedrock wildcard is worse than an S3 wildcard: model invocation is irreversible (data leaves the account in the response), and guardrail/KM manipulation weakens every other control. The blast radius is every Bedrock resource in the account, not one bucket.",
  severity: "critical",
  appliesTo: "iam_statement",
  complianceFrameworks: [OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const stmt = item.statement as AnalyzedStatement;
    const roleName = item.roleName as string;
    const arn = item.roleArn as string;
    const region = item.region as string;

    if (stmt.effect !== "Allow") return null;
    if (!stmt.hasWildcardAction) return null;

    // Only flag if bedrock is in scope (don't flag unrelated wildcards)
    const hasBedrock = stmt.actions.some(a => a.startsWith("bedrock:") || a === "*");
    if (!hasBedrock) return null;

    return finding(
      {
        ruleId: "wildcard-bedrock-action",
        title: `${roleName} has wildcard Bedrock permissions`,
        severity: "critical" as const,
        complianceFrameworks: [OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
      },
      {
        resource: arn,
        region,
        details: `Role "${roleName}" has broad Bedrock access: ${stmt.actions.filter(a => a.startsWith("bedrock:") || a === "*").join(", ")}. Statement SID: ${stmt.sid}.${stmt.hasWildcardResource ? " Resources are also wildcard (*)." : ""}${!stmt.hasCondition ? " No condition keys restrict access." : ""}`,
        remediation: `Replace wildcard actions with scoped bedrock:InvokeModel on specific model ARNs:\n\naws iam put-role-policy --role-name ${roleName} --policy-name scoped-bedrock --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["bedrock:InvokeModel"],"Resource":["arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-*"],"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}'`,
        reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html",
      }
    );
  },
});

// ── Rule: no-condition-keys ────────────────────────────────────
ruleRegistry.register({
  ruleId: "no-condition-keys",
  title: "Bedrock permission lacks condition keys",
  description: "IAM policy allows Bedrock actions without any condition keys (aws:SourceIp, aws:RequestedRegion, etc.). This means the permission can be used from any IP, any region, at any time.",
  threat: "Bedrock access is usable from any IP, any region, at any time. A leaked long-term credential or a compromised SSRF path can invoke models from anywhere.",
  rationale: "Condition keys are the only IAM-layer control that constrains where and when a permission is usable. Without them, geographic and time-based abuse patterns (off-hours exfiltration, unusual-region calls) are structurally unblockable at IAM.",
  severity: "high",
  appliesTo: "iam_statement",
  complianceFrameworks: [OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const stmt = item.statement as AnalyzedStatement;
    const roleName = item.roleName as string;
    const arn = item.roleArn as string;
    const region = item.region as string;

    if (stmt.effect !== "Allow") return null;
    if (stmt.hasCondition) return null;

    const hasBedrock = stmt.actions.some(a => a.startsWith("bedrock:"));
    if (!hasBedrock) return null;

    return finding(
      {
        ruleId: "no-condition-keys",
        title: `${roleName}: Bedrock access has no condition keys`,
        severity: "high",
        complianceFrameworks: [OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
      },
      {
        resource: arn,
        region,
        details: `Role "${roleName}" allows Bedrock actions (${stmt.actions.filter(a => a.startsWith("bedrock:")).join(", ")}) without any condition keys. No IP restriction, no region restriction, no time-based restriction.`,
        remediation: `Add condition keys to restrict the blast radius. Minimum: require aws:RequestedRegion. Best practice: add aws:SourceIp for known IP ranges:\n\n"Condition": {\n  "StringEquals": { "aws:RequestedRegion": "us-east-1" },\n  "IpAddress": { "aws:SourceIp": ["203.0.113.0/24"] }\n}`,
        reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html",
      }
    );
  },
});

// ── Rule: wildcard-principal ───────────────────────────────────
ruleRegistry.register({
  ruleId: "wildcard-principal",
  title: "Bedrock role trust policy allows wildcard principal",
  description: "The role's trust policy allows any AWS principal (*) to assume this role. If this role has Bedrock permissions, any AWS identity could invoke models in your account.",
  threat: "Any AWS principal worldwide can assume this role and invoke models in your account. Cross-tenant and supply-chain actors can consume your model access at your cost and under your account identity.",
  rationale: "Wildcard trust plus Bedrock permissions is the highest-impact IAM misconfiguration for AI workloads: it turns an IAM defect into a direct model-access path for arbitrary external identities. No region or IP condition rescues a Principal: * trust.",
  severity: "critical",
  appliesTo: "iam_role",
  complianceFrameworks: [OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const trustPrincipals = (item.trustPrincipals as string[]) ?? [];
    const roleName = item.roleName as string;
    const arn = item.roleArn as string;
    const region = item.region as string;
    const hasBedrockPerms = item.hasBedrockPermissions as boolean;

    if (!hasBedrockPerms) return null;
    if (!trustPrincipals.includes("*")) return null;

    return finding(
      {
        ruleId: "wildcard-principal",
        title: `${roleName}: trust policy allows wildcard principal`,
        severity: "critical",
        complianceFrameworks: [OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, NIST_AI_RMF],
      },
      {
        resource: arn,
        region,
        details: `Role "${roleName}" has a trust policy that allows any AWS principal ("Principal": "*") to assume it. Combined with its Bedrock permissions, this means any AWS identity worldwide could invoke models in your account.`,
        remediation: `Restrict the trust policy to specific principals, accounts, or service identities. For cross-account access, specify the exact account ARN. For service roles, use the specific service principal (e.g., "bedrock.amazonaws.com").`,
        reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
      }
    );
  },
});

// ── Rule: cross-account-bedrock-access ─────────────────────────
ruleRegistry.register({
  ruleId: "cross-account-bedrock-access",
  title: "Bedrock role is assumable by external AWS account",
  description: "The role's trust policy allows an external AWS account to assume this Bedrock-privileged role. This is a cross-account AI access path.",
  threat: "An external AWS account can assume this Bedrock-privileged role, creating a cross-account AI access path that bypasses your account's own IAM review.",
  rationale: "Cross-account access is sometimes intentional (a trusted partner), but undocumented cross-account Bedrock access is a supply-chain vector (OWASP ASI04). The check surfaces it so it can be verified and ExternalId-enforced, not silently trusted.",
  severity: "high",
  appliesTo: "iam_role",
  complianceFrameworks: [OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, OWASP_AGENTIC.ASI04_SUPPLY_CHAIN, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const externalAccounts = (item.externalAccounts as string[]) ?? [];
    const roleName = item.roleName as string;
    const arn = item.roleArn as string;
    const region = item.region as string;
    const hasBedrockPerms = item.hasBedrockPermissions as boolean;

    if (!hasBedrockPerms) return null;
    if (externalAccounts.length === 0) return null;

    return finding(
      {
        ruleId: "cross-account-bedrock-access",
        title: `${roleName}: Bedrock role assumable by external account(s)`,
        severity: "high",
        complianceFrameworks: [OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, OWASP_AGENTIC.ASI04_SUPPLY_CHAIN, NIST_AI_RMF],
      },
      {
        resource: arn,
        region,
        details: `Role "${roleName}" can be assumed by external AWS account(s): ${externalAccounts.join(", ")}. This creates a cross-account AI access path.`,
        remediation: `Verify the external account(s) are trusted and documented. Add the external account IDs to an allowlist. If cross-account Bedrock access is not intentional, remove the external account from the trust policy. Add the sts:ExternalId condition for additional security.`,
        reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html",
      }
    );
  },
});

// ── Rule: not-action-not-resource ─────────────────────────────
// NotAction / NotResource invert the match and are easy to misread. A statement
// like { Effect: Allow, NotAction: "bedrock:*", Resource: "*" } grants everything
// EXCEPT bedrock — but a statement with Action: "*" and NotResource: <a bedrock
// arn> is exotic and error-prone. Flag any use for manual review rather than
// silently treating the statement as having no actions/resources.
ruleRegistry.register({
  ruleId: "not-action-not-resource",
  title: "Policy statement uses NotAction or NotResource",
  description: "A Bedrock-relevant statement uses NotAction or NotResource. These invert the match semantics and are easy to misread. Manual review required — the rule engine does not collapse them into actions/resources.",
  threat: "Inverted match semantics (NotAction/NotResource) are easy to misread; a reviewer may believe a statement scopes Bedrock when it actually grants everything except Bedrock, or vice versa.",
  rationale: "Automated analysis cannot soundly collapse NotAction into an allow-list. The honest output is to flag for human review rather than produce a false clean or a false fail.",
  severity: "medium",
  appliesTo: "iam_statement",
  complianceFrameworks: [OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
  check(item: Record<string, unknown>) {
    const stmt = item.statement as AnalyzedStatement;
    const roleName = item.roleName as string;
    const arn = item.roleArn as string;
    const region = item.region as string;

    if (!stmt.usesNotAction && !stmt.usesNotResource) return null;

    const elements: string[] = [];
    if (stmt.usesNotAction) elements.push("NotAction");
    if (stmt.usesNotResource) elements.push("NotResource");

    return finding(
      {
        ruleId: "not-action-not-resource",
        title: `${roleName}: statement uses ${elements.join(" + ")}`,
        severity: "medium",
        complianceFrameworks: [OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
      },
      {
        resource: arn,
        region,
        details: `Role "${roleName}" has a Bedrock-relevant statement (SID: ${stmt.sid}) using ${elements.join(" and ")}. Inverted match semantics cannot be evaluated automatically — a reviewer must confirm the statement grants only what is intended.`,
        remediation: `Rewrite the statement to use explicit Action and Resource lists. Avoid NotAction/NotResource on Bedrock-relevant statements unless the inversion is deliberately a guardrail (e.g. a Deny with NotAction to exempt a specific model).`,
        reference: "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html",
      }
    );
  },
});
