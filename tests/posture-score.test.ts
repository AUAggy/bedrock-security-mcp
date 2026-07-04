import { describe, it, expect } from "vitest";
import { computePostureScore } from "../src/report/markdown.js";
import type { BedrockSecurityFinding, Severity, FindingStatus } from "../src/types.js";

function f(severity: Severity, status: FindingStatus = "FAIL"): BedrockSecurityFinding {
  return {
    findingId: `t-${severity}-${Math.random()}`,
    ruleId: "test-rule",
    title: "test",
    severity,
    status,
    resource: "arn:test",
    region: "global",
    details: "",
    remediation: "",
    complianceFrameworks: ["NIST_AI_RMF"],
  };
}

describe("computePostureScore", () => {
  it("scores 100 with no findings", () => {
    expect(computePostureScore([])).toBe(100);
  });

  it("scores 100 with only PASS/ERROR/NOT_APPLICABLE findings", () => {
    expect(computePostureScore([f("low", "PASS"), f("critical", "ERROR"), f("medium", "NOT_APPLICABLE")])).toBe(100);
  });

  it("caps at 75 with one critical", () => {
    expect(computePostureScore([f("critical")])).toBe(75);
  });

  it("floors at 0 with four criticals", () => {
    expect(computePostureScore([f("critical"), f("critical"), f("critical"), f("critical")])).toBe(0);
  });

  it("never goes below 0", () => {
    expect(computePostureScore(Array.from({ length: 10 }, () => f("critical")))).toBe(0);
  });

  it("weights high=10, medium=3, low=1", () => {
    expect(computePostureScore([f("high")])).toBe(90);
    expect(computePostureScore([f("medium")])).toBe(97);
    expect(computePostureScore([f("low")])).toBe(99);
    expect(computePostureScore([f("critical"), f("high"), f("medium"), f("low")])).toBe(100 - 25 - 10 - 3 - 1);
  });
});
