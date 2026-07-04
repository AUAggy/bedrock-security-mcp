import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { analyzeStatement, hasBedrockActions } from "../src/analysis/policy.js";

function fixture(name: string): any {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf-8"));
}

const roleA = fixture("role-wildcard-action.json");
const roleB = fixture("role-scoped-with-conditions.json");
const roleF = fixture("role-not-action.json");

describe("analyzeStatement", () => {
  it("flags wildcard action and wildcard resource on Role A (bedrock:* on *)", () => {
    const stmt = analyzeStatement(roleA.inlinePolicies["bedrock-wildcard"].Statement[0]);
    expect(stmt.effect).toBe("Allow");
    expect(stmt.actions).toEqual(["bedrock:*"]);
    expect(stmt.hasWildcardAction).toBe(true);
    expect(stmt.hasWildcardResource).toBe(true);
    expect(stmt.hasCondition).toBe(false);
    expect(stmt.usesNotAction).toBe(false);
    expect(stmt.usesNotResource).toBe(false);
  });

  it("treats a bare '*' action as a wildcard", () => {
    const stmt = analyzeStatement({ Effect: "Allow", Action: "*", Resource: "*" });
    expect(stmt.hasWildcardAction).toBe(true);
  });

  it("does not flag Role B's scoped statement with conditions", () => {
    const stmt = analyzeStatement(roleB.inlinePolicies["bedrock-scoped"].Statement[0]);
    expect(stmt.hasWildcardAction).toBe(false);
    expect(stmt.hasWildcardResource).toBe(false);
    expect(stmt.hasCondition).toBe(true);
    expect(stmt.conditionKeys).toContain("aws:RequestedRegion");
    expect(stmt.actions).toEqual(["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]);
  });

  it("detects NotAction on Role F without collapsing it into actions", () => {
    const stmt = analyzeStatement(roleF.inlinePolicies["not-action-trap"].Statement[0]);
    expect(stmt.usesNotAction).toBe(true);
    expect(stmt.actions).toEqual([]);
    expect(stmt.hasWildcardResource).toBe(true);
  });

  it("detects NotResource", () => {
    const stmt = analyzeStatement({
      Effect: "Allow",
      Action: "bedrock:InvokeModel",
      NotResource: "arn:aws:bedrock:*::foundation-model/anthropic.*",
    });
    expect(stmt.usesNotResource).toBe(true);
  });

  it("preserves Deny effect", () => {
    const stmt = analyzeStatement({ Effect: "Deny", Action: "bedrock:*", Resource: "*" });
    expect(stmt.effect).toBe("Deny");
  });

  it("handles missing Action and Resource without throwing", () => {
    const stmt = analyzeStatement({ Effect: "Allow" });
    expect(stmt.actions).toEqual([]);
    expect(stmt.resources).toEqual([]);
    expect(stmt.hasWildcardAction).toBe(false);
    expect(stmt.hasWildcardResource).toBe(false);
  });

  it("normalizes single-string Action/Resource into arrays", () => {
    const stmt = analyzeStatement({ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" });
    expect(stmt.actions).toEqual(["s3:GetObject"]);
    expect(stmt.resources).toEqual(["arn:aws:s3:::b/*"]);
  });
});

describe("hasBedrockActions", () => {
  it("is true for bedrock:* statements", () => {
    const stmt = analyzeStatement(roleA.inlinePolicies["bedrock-wildcard"].Statement[0]);
    expect(hasBedrockActions([stmt])).toBe(true);
  });

  it("is true for NotAction statements (manual review scope)", () => {
    const stmt = analyzeStatement(roleF.inlinePolicies["not-action-trap"].Statement[0]);
    expect(hasBedrockActions([stmt])).toBe(true);
  });

  it("is false for a role with only S3 permissions", () => {
    const stmt = analyzeStatement({ Effect: "Allow", Action: "s3:GetObject", Resource: "*" });
    expect(hasBedrockActions([stmt])).toBe(false);
  });

  it("is false for Deny-only bedrock statements", () => {
    const stmt = analyzeStatement({ Effect: "Deny", Action: "bedrock:*", Resource: "*" });
    expect(hasBedrockActions([stmt])).toBe(false);
  });
});
