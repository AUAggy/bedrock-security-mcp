import { describe, it, expect } from "vitest";
import { buildMarkdownReport, categorizeFinding } from "../src/report/markdown.js";
import { generateHtmlReport } from "../src/report/html.js";
import type { BedrockSecurityFinding } from "../src/types.js";

const OPTS = { region: "us-east-1", accountId: "111122223333" };

function finding(overrides: Partial<BedrockSecurityFinding>): BedrockSecurityFinding {
  return {
    findingId: "f-1",
    ruleId: "wildcard-bedrock-action",
    title: "RoleA has wildcard Bedrock permissions",
    severity: "critical",
    status: "FAIL",
    resource: "arn:aws:iam::111122223333:role/RoleA",
    region: "global",
    details: "Role has bedrock:* on *",
    remediation: "Scope the actions.",
    complianceFrameworks: ["OWASP_LLM_TOP10:LLM06", "NIST_AI_RMF"],
    ...overrides,
  };
}

const FULL_SET: BedrockSecurityFinding[] = [
  finding({}),
  finding({
    findingId: "f-2", ruleId: "wildcard-principal", severity: "critical",
    title: "RoleD: trust policy allows wildcard principal",
    resource: "arn:aws:iam::111122223333:role/RoleD",
  }),
  finding({
    findingId: "f-3", ruleId: "no-condition-keys", severity: "high",
    title: "RoleA: Bedrock access has no condition keys",
  }),
  finding({
    findingId: "f-4", ruleId: "bedrock-logging-disabled", severity: "high",
    title: "Bedrock model-invocation logging disabled",
    resource: "bedrock:model-invocation-logging",
  }),
  finding({
    findingId: "f-5", ruleId: "guardrail-no-pii-filter", severity: "medium",
    title: "Guardrail 'Weak' has no PII filter",
    details: "Guardrail 'Weak' has 0 PII entities | prompts can carry PII unmasked",
    resource: "arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-weak",
  }),
  finding({
    findingId: "f-6", ruleId: "prompt-injection-ignore-previous-instructions", severity: "critical",
    title: "Prompt injection signature detected: ignore-previous-instructions",
    details: `Request body contains "<script>" & special chars | pipes`,
    resource: "arn:aws:sts::111122223333:assumed-role/app/worker",
  }),
  finding({
    findingId: "f-7", ruleId: "excessive-token-usage", severity: "low",
    title: "High token count Bedrock invocation: 150000 tokens",
  }),
  finding({
    findingId: "f-8", ruleId: "no-injection-signals", severity: "low", status: "PASS",
    title: "No prompt injection signals detected",
  }),
  finding({
    findingId: "f-9", ruleId: "policy-parse-error", severity: "medium", status: "ERROR",
    title: "Could not parse a policy document for RoleG",
  }),
];

describe("categorizeFinding", () => {
  it("bins IAM rules under IAM & Access via the catalog appliesTo scope", () => {
    for (const id of ["wildcard-bedrock-action", "no-condition-keys", "wildcard-principal", "cross-account-bedrock-access", "not-action-not-resource"]) {
      expect(categorizeFinding(id), id).toBe("IAM & Access");
    }
  });

  it("bins detection rules under Prompt Injection", () => {
    for (const id of ["prompt-injection-ignore-previous-instructions", "off-hours-bedrock-usage", "guardrail-less-invocation", "cloudtrail-management-disabled", "excessive-token-usage"]) {
      expect(categorizeFinding(id), id).toBe("Prompt Injection");
    }
  });

  it("bins config/guardrail rules under Bedrock Configuration", () => {
    for (const id of ["bedrock-logging-disabled", "invocation-logs-without-cmk", "guardrail-content-filter-weak", "guardrail-no-pii-filter", "guardrail-no-denied-topics", "guardrail-grounding-disabled", "prompt-scan-logging-unavailable"]) {
      expect(categorizeFinding(id), id).toBe("Bedrock Configuration");
    }
  });

  it("bins synthetic non-catalog ruleIds sensibly", () => {
    expect(categorizeFinding("policy-parse-error")).toBe("IAM & Access");
    expect(categorizeFinding("iam-enumeration-error")).toBe("IAM & Access");
    expect(categorizeFinding("no-injection-signals")).toBe("Prompt Injection");
    expect(categorizeFinding("invalid-input")).toBe("Prompt Injection");
    expect(categorizeFinding("guardrail-read-error")).toBe("Bedrock Configuration");
  });
});

describe("buildMarkdownReport", () => {
  it("renders without throwing on empty findings", () => {
    const md = buildMarkdownReport([], OPTS);
    expect(md).toContain("No security violations detected");
    expect(md).toContain("100/100");
  });

  it("groups exec-summary categories correctly on a full set", () => {
    const md = buildMarkdownReport(FULL_SET, OPTS);
    expect(md).toContain("**IAM & Access:**");
    expect(md).toContain("**Prompt Injection:**");
    expect(md).toContain("**Bedrock Configuration:**");
  });

  it("renders all major sections on a full set", () => {
    const md = buildMarkdownReport(FULL_SET, OPTS);
    expect(md).toContain("## Executive Summary");
    expect(md).toContain("**Overall Risk Rating:** CRITICAL");
    expect(md).toContain("## Severity Breakdown");
    expect(md).toContain("## Critical Findings");
    expect(md).toContain("## High Findings");
    expect(md).toContain("## Other Findings");
    expect(md).toContain("## Remediation Roadmap");
    expect(md).toContain("## Compliance Mapping");
    expect(md).toContain("## Posture Score");
    expect(md).toContain("111122223333");
  });

  it("renders threat/rationale for cataloged rules", () => {
    const md = buildMarkdownReport(FULL_SET, OPTS);
    expect(md).toContain("**Threat:** A compromised principal with bedrock:*");
    expect(md).toContain("**Why it matters:**");
  });

  it("respects a custom title", () => {
    const md = buildMarkdownReport([], { ...OPTS, title: "Custom Report Title" });
    expect(md.startsWith("# Custom Report Title")).toBe(true);
  });

  it("escapes pipes in table summaries", () => {
    const md = buildMarkdownReport(FULL_SET, OPTS);
    expect(md).toContain("\\|");
  });
});

describe("generateHtmlReport", () => {
  it("renders without throwing on empty findings", () => {
    const html = generateHtmlReport([], OPTS);
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("All checks passed");
  });

  it("renders finding cards with globally unique IDs", () => {
    const html = generateHtmlReport(FULL_SET, OPTS);
    const ids = [...html.matchAll(/id="(finding-[a-z]+-\d+)"/g)].map(m => m[1]);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("renders threat and rationale rows for cataloged rules", () => {
    const html = generateHtmlReport(FULL_SET, OPTS);
    expect(html).toContain(">Threat<");
    expect(html).toContain(">Why this matters<");
    expect(html).toContain("A compromised principal with bedrock:*");
  });

  it("escapes HTML-sensitive characters from finding content", () => {
    const html = generateHtmlReport(FULL_SET, OPTS);
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>\" & special");
    expect(html).toContain("&amp; special chars");
  });

  it("shows the severity bar, roadmap, compliance mapping, and passed section", () => {
    const html = generateHtmlReport(FULL_SET, OPTS);
    expect(html).toContain('class="severity-bar"');
    expect(html).toContain("Remediation roadmap");
    expect(html).toContain("Compliance mapping");
    expect(html).toContain("Passed checks (1)");
    expect(html).toContain("Overall risk: Critical");
  });

  it("includes account, region, and framework footer", () => {
    const html = generateHtmlReport(FULL_SET, OPTS);
    expect(html).toContain("111122223333");
    expect(html).toContain("us-east-1");
    expect(html).toContain("MITRE ATLAS");
  });
});
