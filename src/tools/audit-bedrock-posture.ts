// src/tools/audit-bedrock-posture.ts

import { IAMClient } from "@aws-sdk/client-iam";
import {
  BedrockClient,
  GetModelInvocationLoggingConfigurationCommand,
} from "@aws-sdk/client-bedrock";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import {
  listAllRoles,
  listAttachedPolicies,
  listInlinePolicyNames,
  getInlinePolicyDocument,
  getManagedPolicyDocument,
  type RoleSummary,
} from "../aws/iam.js";
import {
  analyzeStatement,
  hasBedrockActions,
  parseTrustPolicy,
  extractAccountIdFromArn,
} from "../analysis/policy.js";
import { listGuardrails, getGuardrailConfig } from "../aws/bedrock.js";
import { ruleRegistry } from "../rules/registry.js";
// Import rule files to trigger registration
import "../rules/iam-rules.js";
import "../rules/bedrock-rules.js";
import { NIST_AI_RMF, AWS_WA_ML_LENS } from "../compliance.js";
import type { BedrockSecurityFinding, AnalyzedStatement } from "../types.js";

interface AuditBedrockPostureInput {
  roleName?: string;         // Optional: audit a single role
  region?: string;           // Default: from AWS_REGION or us-east-1
}

/** IAM role-enumeration concurrency. Bounded so large accounts (300+ roles)
 * audit in seconds without tripping IAM's account-level API throttling; the
 * SDK's adaptive retry absorbs transient throttles. */
const ROLE_CONCURRENCY = 8;

/** Minimal bounded-concurrency map. Results are indexed by input position, so
 * output order is deterministic regardless of completion order (TEST_PLAN C8). */
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function auditBedrockPosture(
  input: AuditBedrockPostureInput,
  region: string
): Promise<BedrockSecurityFinding[]> {
  // IAM is a global service. The client needs a region for signing, but findings
  // are stamped "global" so readers do not mistake a global role for a regional one.
  const iam = new IAMClient({ region });
  const bedrock = new BedrockClient({ region });
  const IAM_REGION = "global";

  // ── 1. Logging config + invocation-log KMS + guardrails ────
  const configFindings: BedrockSecurityFinding[] = [];
  const configItems: Array<{ scope: string; data: Record<string, unknown> }> = [];
  let cloudWatchLogGroupName: string | undefined;

  try {
    const loggingConfig = await bedrock.send(new GetModelInvocationLoggingConfigurationCommand({}));
    const cwCfg = loggingConfig.loggingConfig?.cloudWatchConfig;
    const s3Cfg = loggingConfig.loggingConfig?.s3Config;
    const loggingEnabled = !!(cwCfg?.logGroupName || s3Cfg?.bucketName);
    if (cwCfg?.logGroupName) cloudWatchLogGroupName = cwCfg.logGroupName;

    // KMS check on the CloudWatch log group (if configured). DescribeLogGroups is
    // on the same client Tool 2 uses for FilterLogEvents — no new dependency.
    let kmsKeyId: string | undefined;
    if (cloudWatchLogGroupName) {
      try {
        const logs = new CloudWatchLogsClient({ region });
        const dl = await logs.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: cloudWatchLogGroupName }));
        kmsKeyId = dl.logGroups?.find(g => g.logGroupName === cloudWatchLogGroupName)?.kmsKeyId;
      } catch (err) {
        configFindings.push({
          findingId: "invocation-logs-kms-check-error",
          ruleId: "invocation-logs-without-cmk",
          title: "Could not check invocation log KMS configuration",
          severity: "low",
          status: "ERROR",
          resource: `arn:aws:logs:::log-group:${cloudWatchLogGroupName}`,
          region: IAM_REGION,
          details: `Failed to call DescribeLogGroups for '${cloudWatchLogGroupName}': ${(err as Error).message}`,
          remediation: "Verify IAM permissions: logs:DescribeLogGroups on the Bedrock invocation log group.",
          complianceFrameworks: [AWS_WA_ML_LENS.SEC_6, NIST_AI_RMF],
        });
      }
    }

    configItems.push({
      scope: "bedrock_config",
      data: { loggingEnabled, kmsKeyId, logGroupName: cloudWatchLogGroupName, region: IAM_REGION },
    });
  } catch (err) {
    configFindings.push({
      findingId: "bedrock-logging-check-error",
      ruleId: "bedrock-logging-disabled",
      title: "Could not check Bedrock logging configuration",
      severity: "low",
      status: "ERROR",
      resource: "bedrock:model-invocation-logging",
      region: IAM_REGION,
      details: `Failed to call GetModelInvocationLoggingConfiguration: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: bedrock:GetModelInvocationLoggingConfiguration",
      complianceFrameworks: ["NIST_AI_RMF", "MITRE_ATLAS"],
    });
  }

  // Guardrail audit. Each guardrail's normalized config is fed to the rule engine.
  try {
    const guardrails = await listGuardrails(bedrock);
    for (const g of guardrails) {
      const { config, error } = await getGuardrailConfig(bedrock, g);
      if (error || !config) {
        configFindings.push({
          findingId: `guardrail-read-error-${g.guardrailId}`,
          ruleId: "guardrail-read-error",
          title: `Could not read guardrail ${g.name}`,
          severity: "low",
          status: "ERROR",
          resource: g.guardrailArn || g.guardrailId,
          region: IAM_REGION,
          details: error ?? `getGuardrailConfig returned no config for ${g.guardrailId}`,
          remediation: "Verify IAM permissions: bedrock:GetGuardrail. Confirm the guardrail still exists.",
          complianceFrameworks: [AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
        });
        continue;
      }
      configItems.push({
        scope: "bedrock_guardrail",
        data: { config, region: IAM_REGION },
      });
    }
  } catch (err) {
    configFindings.push({
      findingId: "guardrail-list-error",
      ruleId: "guardrail-read-error",
      title: "Could not list Bedrock Guardrails",
      severity: "low",
      status: "ERROR",
      resource: "bedrock:guardrails",
      region: IAM_REGION,
      details: `Failed to call ListGuardrails: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: bedrock:ListGuardrails.",
      complianceFrameworks: [AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
    });
  }

  configFindings.push(...ruleRegistry.evaluate(configItems));

  // ── 2. Enumerate roles with Bedrock permissions ────────────
  let roles;
  try {
    roles = await listAllRoles(iam);
  } catch (err) {
    configFindings.push({
      findingId: "iam-list-roles-error",
      ruleId: "iam-enumeration-error",
      title: "Could not enumerate IAM roles",
      severity: "medium",
      status: "ERROR",
      resource: "iam:roles",
      region: IAM_REGION,
      details: `Failed to call ListRoles: ${(err as Error).message}`,
      remediation: "Verify AWS credentials are configured and the principal has iam:ListRoles. The IAM posture audit could not run.",
      complianceFrameworks: [AWS_WA_ML_LENS.SEC_3, NIST_AI_RMF],
    });
    return configFindings;
  }
  const filteredRoles = input.roleName
    ? roles.filter(r => r.roleName === input.roleName)
    : roles;

  // Resolve the current account ID from the first role ARN. No sts:GetCallerIdentity
  // call, no new permission — every role ARN contains the account ID.
  const currentAccountId = roles.length > 0
    ? extractAccountIdFromArn(roles[0].arn)
    : null;

  // Managed-policy document cache: AmazonBedrockFullAccess attached to 50 roles
  // is loaded once, not 50 times. Caches the *promise* so concurrent workers
  // that miss simultaneously await one in-flight request instead of duplicating
  // it. Every role attached to an unparseable policy surfaces the parse error
  // (fail-closed per role, not just for the first requester).
  const managedPolicyCache = new Map<string, Promise<{ doc: Record<string, unknown> | null; parseError?: string }>>();
  const getManagedPolicyCached = (arn: string) => {
    let pending = managedPolicyCache.get(arn);
    if (!pending) {
      pending = getManagedPolicyDocument(iam, arn);
      managedPolicyCache.set(arn, pending);
    }
    return pending;
  };

  interface RoleAuditResult {
    ruleItems: Array<{ scope: string; data: Record<string, unknown> }>;
    parseErrorFindings: BedrockSecurityFinding[];
  }

  const processRole = async (role: RoleSummary): Promise<RoleAuditResult> => {
    const ruleItems: Array<{ scope: string; data: Record<string, unknown> }> = [];
    const parseErrorFindings: BedrockSecurityFinding[] = [];
    const allStatements: AnalyzedStatement[] = [];
    const parseErrors: string[] = [];

    // 2a. Attached managed policies (cached by ARN)
    const policyArns = await listAttachedPolicies(iam, role.roleName);
    for (const arn of policyArns) {
      const result = await getManagedPolicyCached(arn);
      const doc = result.doc;
      if (result.parseError) parseErrors.push(result.parseError);
      if (doc && (doc as any).Statement) {
        const statements = Array.isArray((doc as any).Statement)
          ? (doc as any).Statement
          : [(doc as any).Statement];
        for (const stmt of statements) {
          allStatements.push(analyzeStatement(stmt));
        }
      }
    }

    // 2b. Inline policies — the classic place to hide bedrock:*. These are NOT
    // optional: a security tool that skips inline policies is fail-open.
    const inlineNames = await listInlinePolicyNames(iam, role.roleName);
    for (const policyName of inlineNames) {
      const result = await getInlinePolicyDocument(iam, role.roleName, policyName);
      if (result.parseError) {
        parseErrors.push(result.parseError);
        continue;
      }
      const doc = result.doc;
      if (doc && (doc as any).Statement) {
        const statements = Array.isArray((doc as any).Statement)
          ? (doc as any).Statement
          : [(doc as any).Statement];
        for (const stmt of statements) {
          allStatements.push(analyzeStatement(stmt));
        }
      }
    }

    // 2c. Parse the trust policy for wildcard-principal + cross-account rules.
    const trust = parseTrustPolicy(role.assumeRolePolicyDocument, currentAccountId);
    if (trust.parseError) parseErrors.push(trust.parseError);

    // 2d. Surface parse failures as ERROR findings directly — never route them
    // through the rule engine (rules return null for non-Allow statements, so a
    // parse-error synthetic statement would be silently skipped = fail-open).
    for (const msg of parseErrors) {
      parseErrorFindings.push({
        findingId: `policy-parse-error-${role.roleName}-${msg.length}`,
        ruleId: "policy-parse-error",
        title: `Could not parse a policy document for ${role.roleName}`,
        severity: "medium",
        status: "ERROR",
        resource: role.arn,
        region: IAM_REGION,
        details: msg,
        remediation: "Inspect the role's inline and managed policies in the AWS console. A malformed or non-standard policy document prevented automatic analysis — review it manually rather than treating the role as clean.",
        complianceFrameworks: [NIST_AI_RMF, AWS_WA_ML_LENS.SEC_3],
      });
    }

    // 2e. If any statement involves Bedrock, feed statements + role metadata to
    // the rule engine. Also surface a parse-error finding if trust/policy docs
    // were unparseable so a human investigates rather than seeing a clean pass.
    const hasBedrock = hasBedrockActions(allStatements) || parseErrors.length > 0;
    if (hasBedrock) {
      for (const stmt of allStatements) {
        if (stmt.effect !== "Allow") continue;
        ruleItems.push({
          scope: "iam_statement",
          data: {
            statement: stmt,
            roleName: role.roleName,
            roleArn: role.arn,
            region: IAM_REGION,
          },
        });
      }

      ruleItems.push({
        scope: "iam_role",
        data: {
          roleName: role.roleName,
          roleArn: role.arn,
          region: IAM_REGION,
          hasBedrockPermissions: hasBedrockActions(allStatements),
          trustPrincipals: trust.principals,
          externalAccounts: trust.externalAccounts,
        },
      });
    }

    return { ruleItems, parseErrorFindings };
  };

  // Bounded-parallel role processing; results flattened in role-list order so
  // output stays deterministic (TEST_PLAN C8).
  const perRole = await mapWithConcurrency(filteredRoles, ROLE_CONCURRENCY, processRole);
  const ruleItems = perRole.flatMap(r => r.ruleItems);
  const parseErrorFindings = perRole.flatMap(r => r.parseErrorFindings);

  // ── 3. Evaluate all rules ──────────────────────────────────
  const iamFindings = ruleRegistry.evaluate(ruleItems);

  return [...configFindings, ...parseErrorFindings, ...iamFindings];
}
