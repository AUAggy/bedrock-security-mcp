import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { ruleRegistry } from "../src/rules/registry.js";
import "../src/rules/iam-rules.js";
import { analyzeStatement, parseTrustPolicy } from "../src/analysis/policy.js";

function fixture(name: string): any {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf-8"));
}

const ACCOUNT = "111122223333";
const REGION = "global";

const roleA = fixture("role-wildcard-action.json");
const roleB = fixture("role-scoped-with-conditions.json");
const roleD = fixture("role-wildcard-principal-trust.json");
const roleE = fixture("role-cross-account-trust.json");
const roleF = fixture("role-not-action.json");

function statementItem(role: any, policyName: string) {
  return {
    statement: analyzeStatement(role.inlinePolicies[policyName].Statement[0]),
    roleName: role.roleName,
    roleArn: role.arn,
    region: REGION,
  };
}

function roleItem(role: any) {
  const trust = parseTrustPolicy(role.assumeRolePolicyDocument, ACCOUNT);
  return {
    roleName: role.roleName,
    roleArn: role.arn,
    region: REGION,
    hasBedrockPermissions: true,
    trustPrincipals: trust.principals,
    externalAccounts: trust.externalAccounts,
  };
}

function rule(ruleId: string) {
  const spec = ruleRegistry.get(ruleId);
  expect(spec, `rule ${ruleId} must be registered`).toBeDefined();
  return spec!;
}

describe("wildcard-bedrock-action", () => {
  it("fires critical on Role A (bedrock:* on *)", () => {
    const f = rule("wildcard-bedrock-action").check(statementItem(roleA, "bedrock-wildcard"));
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("critical");
    expect(f!.status).toBe("FAIL");
    expect(f!.resource).toBe(roleA.arn);
    expect(f!.region).toBe(REGION);
    expect(f!.details).toContain("bedrock:*");
    expect(f!.complianceFrameworks.length).toBeGreaterThan(0);
  });

  it("is suppressed on Role B (scoped actions)", () => {
    const f = rule("wildcard-bedrock-action").check(statementItem(roleB, "bedrock-scoped"));
    expect(f).toBeNull();
  });

  it("is suppressed on Deny statements", () => {
    const item = statementItem(roleA, "bedrock-wildcard");
    (item.statement as any).effect = "Deny";
    expect(rule("wildcard-bedrock-action").check(item)).toBeNull();
  });

  it("ignores non-Bedrock wildcards (s3:*)", () => {
    const item = {
      statement: analyzeStatement({ Effect: "Allow", Action: "s3:*", Resource: "*" }),
      roleName: "S3Role", roleArn: "arn:aws:iam::111122223333:role/S3Role", region: REGION,
    };
    expect(rule("wildcard-bedrock-action").check(item)).toBeNull();
  });
});

describe("no-condition-keys", () => {
  it("fires high on Role A (no conditions)", () => {
    const f = rule("no-condition-keys").check(statementItem(roleA, "bedrock-wildcard"));
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("high");
  });

  it("is suppressed on Role B (has aws:RequestedRegion condition)", () => {
    expect(rule("no-condition-keys").check(statementItem(roleB, "bedrock-scoped"))).toBeNull();
  });
});

describe("wildcard-principal", () => {
  it("fires critical on Role D and cites OWASP LLM06 + ASI03", () => {
    const f = rule("wildcard-principal").check(roleItem(roleD));
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("critical");
    expect(f!.complianceFrameworks).toContain("OWASP_LLM_TOP10:LLM06");
    expect(f!.complianceFrameworks).toContain("OWASP_AGENTIC:ASI03");
  });

  it("is suppressed when the role has no Bedrock permissions", () => {
    const item = { ...roleItem(roleD), hasBedrockPermissions: false };
    expect(rule("wildcard-principal").check(item)).toBeNull();
  });

  it("is suppressed on Role B (account-scoped trust)", () => {
    expect(rule("wildcard-principal").check(roleItem(roleB))).toBeNull();
  });
});

describe("cross-account-bedrock-access", () => {
  it("fires high on Role E and names both external accounts", () => {
    const f = rule("cross-account-bedrock-access").check(roleItem(roleE));
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("high");
    expect(f!.details).toContain("999988887777");
    expect(f!.details).toContain("555566667777");
    expect(f!.complianceFrameworks).toContain("OWASP_AGENTIC:ASI03");
    expect(f!.complianceFrameworks).toContain("OWASP_AGENTIC:ASI04");
    expect(f!.complianceFrameworks).toContain("NIST_AI_RMF");
  });

  it("is suppressed on same-account trust (Role B)", () => {
    expect(rule("cross-account-bedrock-access").check(roleItem(roleB))).toBeNull();
  });
});

describe("not-action-not-resource", () => {
  it("fires medium on Role F and names NotAction", () => {
    const f = rule("not-action-not-resource").check(statementItem(roleF, "not-action-trap"));
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("medium");
    expect(f!.details).toContain("NotAction");
  });

  it("is suppressed on plain Action statements", () => {
    expect(rule("not-action-not-resource").check(statementItem(roleB, "bedrock-scoped"))).toBeNull();
  });
});

describe("rule engine evaluate()", () => {
  it("produces both wildcard-bedrock-action and no-condition-keys for Role A via scopes", () => {
    const findings = ruleRegistry.evaluate([
      { scope: "iam_statement", data: statementItem(roleA, "bedrock-wildcard") },
      { scope: "iam_role", data: roleItem(roleA) },
    ]);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain("wildcard-bedrock-action");
    expect(ruleIds).toContain("no-condition-keys");
    expect(ruleIds).not.toContain("wildcard-principal");
  });
});
