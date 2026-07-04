import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { allRuleMetadata, getRuleMetadata } from "../src/rules/catalog.js";

/** Every ruleId a tool can emit as a FAIL/PASS-relevant finding must resolve. */
const EMITTED_RULE_IDS = [
  // Tool 1 registry rules (5 IAM + 6 Bedrock config/guardrail)
  "wildcard-bedrock-action",
  "no-condition-keys",
  "wildcard-principal",
  "cross-account-bedrock-access",
  "not-action-not-resource",
  "bedrock-logging-disabled",
  "invocation-logs-without-cmk",
  "guardrail-content-filter-weak",
  "guardrail-no-pii-filter",
  "guardrail-no-denied-topics",
  "guardrail-grounding-disabled",
  // Tool 2 detection findings
  "prompt-injection-ignore-previous-instructions",
  "prompt-injection-system-prompt-leak",
  "prompt-injection-roleplay-jailbreak",
  "prompt-injection-token-smuggling",
  "off-hours-bedrock-usage",
  "guardrail-less-invocation",
  "cloudtrail-management-disabled",
  "excessive-token-usage",
  "prompt-scan-logging-unavailable",
];

describe("allRuleMetadata", () => {
  it("returns exactly 17 catalog entries", () => {
    expect(allRuleMetadata()).toHaveLength(17);
  });

  it("has no duplicate ruleIds", () => {
    const ids = allRuleMetadata().map(r => r.ruleId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("has non-empty threat and rationale on every entry", () => {
    for (const r of allRuleMetadata()) {
      expect(r.threat.length, `${r.ruleId} threat`).toBeGreaterThan(20);
      expect(r.rationale.length, `${r.ruleId} rationale`).toBeGreaterThan(20);
      expect(r.complianceFrameworks.length, `${r.ruleId} frameworks`).toBeGreaterThan(0);
      expect(r.title.length, `${r.ruleId} title`).toBeGreaterThan(0);
    }
  });
});

describe("getRuleMetadata", () => {
  it("resolves every ruleId the tools emit", () => {
    for (const id of EMITTED_RULE_IDS) {
      expect(getRuleMetadata(id), `ruleId '${id}' must resolve`).toBeDefined();
    }
  });

  it("resolves signature variants to the prompt-injection-* wildcard entry", () => {
    const meta = getRuleMetadata("prompt-injection-ignore-previous-instructions");
    expect(meta).toBeDefined();
    expect(meta!.ruleId).toBe("prompt-injection-*");
    expect(meta!.severity).toBe("critical");
  });

  it("prefers exact matches over wildcard matches", () => {
    expect(getRuleMetadata("off-hours-bedrock-usage")!.ruleId).toBe("off-hours-bedrock-usage");
  });

  it("returns undefined for unknown ruleIds", () => {
    expect(getRuleMetadata("made-up-rule")).toBeUndefined();
  });
});

describe("examples/rules-catalog.json", () => {
  it("matches allRuleMetadata() exactly (regenerate via npm run build:catalog)", () => {
    const artifact = JSON.parse(
      readFileSync(new URL("../examples/rules-catalog.json", import.meta.url), "utf-8")
    );
    const expected = allRuleMetadata().map(r => ({
      ruleId: r.ruleId,
      title: r.title,
      severity: r.severity,
      appliesTo: r.appliesTo,
      complianceFrameworks: r.complianceFrameworks,
      threat: r.threat,
      rationale: r.rationale,
    }));
    expect(artifact.rules).toEqual(expected);
  });
});
