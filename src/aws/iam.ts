// src/aws/iam.ts

import {
  IAMClient,
  ListRolesCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  ListAttachedRolePoliciesCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
} from "@aws-sdk/client-iam";

/** Thin wrappers over AWS SDK. All read-only. */

export interface RoleSummary {
  roleName: string;
  roleId: string;
  arn: string;
  createDate: Date;
  path: string;
  /** Raw (URL-encoded) trust policy document from ListRoles. */
  assumeRolePolicyDocument: string;
}

export async function listAllRoles(iam: IAMClient): Promise<RoleSummary[]> {
  const roles: RoleSummary[] = [];
  let marker: string | undefined;
  do {
    // MaxItems 500 cuts round-trips on large accounts (IAM ListRoles max is 1000).
    const resp = await iam.send(new ListRolesCommand({ Marker: marker, MaxItems: 500 }));
    for (const r of resp.Roles ?? []) {
      roles.push({
        roleName: r.RoleName ?? "unknown",
        roleId: r.RoleId ?? "",
        arn: r.Arn ?? "",
        createDate: r.CreateDate ?? new Date(),
        path: r.Path ?? "/",
        assumeRolePolicyDocument: r.AssumeRolePolicyDocument ?? "",
      });
    }
    marker = resp.Marker;
  } while (marker);
  return roles;
}

// Pure analysis functions (extractAccountIdFromArn, parseTrustPolicy,
// analyzeStatement, hasBedrockActions) live in src/analysis/policy.ts.
// They have no AWS-SDK dependency and are unit-tested without mocks.

/** Get attached managed policy document */
export async function getManagedPolicyDocument(
  iam: IAMClient,
  policyArn: string
): Promise<{ doc: Record<string, unknown> | null; parseError?: string }> {
  try {
    const policy = await iam.send(new GetPolicyCommand({ PolicyArn: policyArn }));
    const version = await iam.send(
      new GetPolicyVersionCommand({
        PolicyArn: policyArn,
        VersionId: policy.Policy?.DefaultVersionId ?? "v1",
      })
    );
    const raw = version.PolicyVersion?.Document;
    if (!raw) return { doc: null };
    let text = raw;
    try {
      text = decodeURIComponent(raw);
    } catch {
      /* already decoded */
    }
    try {
      return { doc: JSON.parse(text) as Record<string, unknown> };
    } catch (err) {
      return { doc: null, parseError: `Could not parse managed policy '${policyArn}': ${(err as Error).message}` };
    }
  } catch (err) {
    return { doc: null, parseError: `Could not read managed policy '${policyArn}': ${(err as Error).message}` };
  }
}

/** List all attached managed policies for a role */
export async function listAttachedPolicies(
  iam: IAMClient,
  roleName: string
): Promise<string[]> {
  const arns: string[] = [];
  let marker: string | undefined;
  do {
    const resp = await iam.send(
      new ListAttachedRolePoliciesCommand({ RoleName: roleName, Marker: marker })
    );
    for (const p of resp.AttachedPolicies ?? []) {
      if (p.PolicyArn) arns.push(p.PolicyArn);
    }
    marker = resp.Marker;
  } while (marker);
  return arns;
}

/** List the names of inline policies embedded directly on a role. */
export async function listInlinePolicyNames(
  iam: IAMClient,
  roleName: string
): Promise<string[]> {
  const names: string[] = [];
  let marker: string | undefined;
  do {
    const resp = await iam.send(
      new ListRolePoliciesCommand({ RoleName: roleName, Marker: marker })
    );
    for (const n of resp.PolicyNames ?? []) {
      if (n) names.push(n);
    }
    marker = resp.Marker;
  } while (marker);
  return names;
}

/**
 * Fetch and parse an inline policy document.
 * Returns `{ doc, parseError }` — never throws. A parse failure is reported
 * to the caller so it can surface as an ERROR finding rather than a silent pass.
 */
export async function getInlinePolicyDocument(
  iam: IAMClient,
  roleName: string,
  policyName: string
): Promise<{ doc: Record<string, unknown> | null; parseError?: string }> {
  try {
    const resp = await iam.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: policyName }));
    const raw = resp.PolicyDocument;
    if (!raw) return { doc: null };
    let text = raw;
    try {
      text = decodeURIComponent(raw);
    } catch {
      /* already decoded */
    }
    try {
      return { doc: JSON.parse(text) as Record<string, unknown> };
    } catch (err) {
      return { doc: null, parseError: `Could not parse inline policy '${policyName}': ${(err as Error).message}` };
    }
  } catch (err) {
    return { doc: null, parseError: `Could not read inline policy '${policyName}': ${(err as Error).message}` };
  }
}
