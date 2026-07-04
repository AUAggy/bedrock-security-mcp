// src/analysis/policy.ts

import type { AnalyzedStatement } from "../types.js";

/** Extract the 12-digit account ID from any IAM role ARN. No API call needed. */
export function extractAccountIdFromArn(arn: string): string | null {
  const m = arn.match(/arn:aws:iam::(\d{12}):/);
  return m ? m[1] : null;
}

/** Result of parsing a role's trust policy. */
export interface ParsedTrustPolicy {
  principals: string[];      // flattened — ["*"] = critical
  externalAccounts: string[];// 12-digit account IDs that differ from the current account
  parseError?: string;       // set if the document could not be parsed
}

/** Parse a URL-encoded AssumeRolePolicyDocument into principal + external-account info. */
export function parseTrustPolicy(
  rawDocument: string,
  currentAccountId: string | null
): ParsedTrustPolicy {
  const result: ParsedTrustPolicy = { principals: [], externalAccounts: [] };
  if (!rawDocument) return result;

  let doc: unknown;
  try {
    let text = rawDocument;
    try {
      text = decodeURIComponent(rawDocument);
    } catch {
      /* already decoded or malformed — use raw */
    }
    doc = JSON.parse(text);
  } catch (err) {
    result.parseError = `Could not parse trust policy: ${(err as Error).message}`;
    return result;
  }

  const statements = Array.isArray((doc as any)?.Statement)
    ? (doc as any).Statement
    : (doc as any)?.Statement ? [(doc as any).Statement] : [];

  const principalSet = new Set<string>();
  const externalSet = new Set<string>();

  for (const stmt of statements) {
    if (!stmt || stmt.Effect !== "Allow") continue;
    const principal = stmt.Principal;
    if (!principal) continue;

    const collectFrom = (val: unknown) => {
      if (typeof val === "string") {
        principalSet.add(val);
        const acct = val.match(/arn:aws:(iam|sts)::(\d{12}):/)?.[2];
        if (acct && acct !== currentAccountId) externalSet.add(acct);
      } else if (Array.isArray(val)) {
        val.forEach(collectFrom);
      } else if (val && typeof val === "object") {
        Object.values(val as Record<string, unknown>).forEach(collectFrom);
      }
    };
    collectFrom(principal);
  }

  result.principals = [...principalSet];
  result.externalAccounts = [...externalSet];
  return result;
}

/** Analyze a single IAM policy statement for Bedrock-specific risks */
export function analyzeStatement(statement: Record<string, unknown>): AnalyzedStatement {
  const effect = (statement.Effect as string) === "Deny" ? "Deny" : "Allow";
  const actions = Array.isArray(statement.Action)
    ? statement.Action.map(String)
    : statement.Action != null
      ? [String(statement.Action)]
      : [];
  const resources = Array.isArray(statement.Resource)
    ? statement.Resource.map(String)
    : statement.Resource != null
      ? [String(statement.Resource)]
      : [];

  // NotAction / NotResource invert the match and are easy to misread. We do not
  // collapse them into actions/resources — we flag them for manual review.
  const notActions = Array.isArray(statement.NotAction)
    ? statement.NotAction.map(String)
    : statement.NotAction != null
      ? [String(statement.NotAction)]
      : [];
  const notResources = Array.isArray(statement.NotResource)
    ? statement.NotResource.map(String)
    : statement.NotResource != null
      ? [String(statement.NotResource)]
      : [];
  const usesNotAction = notActions.length > 0;
  const usesNotResource = notResources.length > 0;

  const hasWildcardAction = actions.some(a => a === "*" || a.includes(":*"));
  const hasWildcardResource = resources.some(r => r === "*");

  const condition = (statement.Condition ?? {}) as Record<string, unknown>;
  const hasCondition = Object.keys(condition).length > 0;
  const conditionKeys = hasCondition
    ? Object.keys(condition).flatMap(op => Object.keys(condition[op] as object))
    : [];

  return {
    sid: String(statement.Sid ?? "Unnamed"),
    effect,
    actions,
    resources,
    hasWildcardAction,
    hasWildcardResource,
    hasCondition,
    conditionKeys,
    principals: [],
    usesNotAction,
    usesNotResource,
  };
}

/** Check if a policy document contains Bedrock-relevant statements */
export function hasBedrockActions(statements: AnalyzedStatement[]): boolean {
  return statements.some(s =>
    s.effect === "Allow" &&
    (s.usesNotAction || s.actions.some(a =>
      a.startsWith("bedrock:") ||
      a === "bedrock:*" ||
      a === "*"
    ))
  );
}
