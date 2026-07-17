// Golden-file suite (engine-extraction Step 1).
//
// Pins the byte-exact output of the engine surfaces that must survive the
// core extraction unchanged: rule evaluation over committed fixtures, the
// markdown report, the HTML report, the CLI --json serialization, and the
// posture score. The extracted engine (bedrock-security-mcp@0.2.0) must keep
// every golden in tests/goldens/ green without regenerating it.
//
// The system clock is frozen so the report "Generated" timestamps are stable.

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { readFileSync } from "node:fs";
import { ruleRegistry } from "../src/rules/registry.js";
import "../src/rules/iam-rules.js";
import "../src/rules/bedrock-rules.js";
import { analyzeStatement, parseTrustPolicy } from "../src/analysis/policy.js";
import { buildMarkdownReport, computePostureScore } from "../src/report/markdown.js";
import { generateHtmlReport } from "../src/report/html.js";
import type { BedrockSecurityFinding } from "../src/types.js";

function fixture(name: string): any {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf-8"));
}

const ACCOUNT = "111122223333";
const REGION = "global";
const REPORT_OPTS = { region: "us-east-1", accountId: ACCOUNT };

const FULL_SET: BedrockSecurityFinding[] = fixture("golden/findings-full.json");

beforeAll(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-07-04T00:00:00Z"));
});

afterAll(() => {
  vi.useRealTimers();
});

describe("golden: rule evaluation pipeline", () => {
  it("produces byte-identical findings over the committed fixtures", async () => {
    const roleA = fixture("role-wildcard-action.json");
    const roleB = fixture("role-scoped-with-conditions.json");
    const roleD = fixture("role-wildcard-principal-trust.json");
    const roleE = fixture("role-cross-account-trust.json");
    const roleF = fixture("role-not-action.json");
    const scenario = fixture("golden/bedrock-scenario.json");

    const statementItem = (role: any, policyName: string) => ({
      scope: "iam_statement",
      data: {
        statement: analyzeStatement(role.inlinePolicies[policyName].Statement[0]),
        roleName: role.roleName,
        roleArn: role.arn,
        region: REGION,
      },
    });

    const roleItem = (role: any) => {
      const trust = parseTrustPolicy(role.assumeRolePolicyDocument, ACCOUNT);
      return {
        scope: "iam_role",
        data: {
          roleName: role.roleName,
          roleArn: role.arn,
          region: REGION,
          hasBedrockPermissions: true,
          trustPrincipals: trust.principals,
          externalAccounts: trust.externalAccounts,
        },
      };
    };

    const findings = ruleRegistry.evaluate([
      statementItem(roleA, "bedrock-wildcard"),
      statementItem(roleB, "bedrock-scoped"),
      statementItem(roleF, "not-action-trap"),
      roleItem(roleA),
      roleItem(roleB),
      roleItem(roleD),
      roleItem(roleE),
      ...scenario.guardrails.map((g: any) => ({
        scope: "bedrock_guardrail",
        data: { config: g, region: REGION },
      })),
      ...scenario.configs.map((c: any) => ({
        scope: "bedrock_config",
        data: c,
      })),
    ]);

    await expect(JSON.stringify(findings, null, 2) + "\n")
      .toMatchFileSnapshot("goldens/pipeline-findings.json");
  });
});

describe("golden: markdown report", () => {
  it("full finding set", async () => {
    await expect(buildMarkdownReport(FULL_SET, REPORT_OPTS))
      .toMatchFileSnapshot("goldens/report-full.md");
  });

  it("empty finding set", async () => {
    await expect(buildMarkdownReport([], REPORT_OPTS))
      .toMatchFileSnapshot("goldens/report-empty.md");
  });
});

describe("golden: HTML report", () => {
  it("full finding set", async () => {
    await expect(generateHtmlReport(FULL_SET, REPORT_OPTS))
      .toMatchFileSnapshot("goldens/report-full.html");
  });

  it("empty finding set", async () => {
    await expect(generateHtmlReport([], REPORT_OPTS))
      .toMatchFileSnapshot("goldens/report-empty.html");
  });
});

describe("golden: CLI --json serialization", () => {
  it("matches the committed byte-exact form", async () => {
    // Exactly what cli.ts prints for --json.
    await expect(JSON.stringify(FULL_SET, null, 2) + "\n")
      .toMatchFileSnapshot("goldens/cli-findings.json");
  });
});

describe("golden: posture score", () => {
  it("pins the exact score for the full fixture set", () => {
    // FAIL deductions: 3 critical (75) + 2 high (20) + 1 medium (3) + 1 low (1) = 99.
    // PASS and ERROR findings deduct nothing.
    expect(computePostureScore(FULL_SET)).toBe(1);
  });

  it("pins the clean-account score", () => {
    expect(computePostureScore([])).toBe(100);
  });
});
