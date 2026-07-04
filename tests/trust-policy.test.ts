import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { parseTrustPolicy, extractAccountIdFromArn } from "../src/analysis/policy.js";

function fixture(name: string): any {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf-8"));
}

const ACCOUNT = "111122223333";
const roleD = fixture("role-wildcard-principal-trust.json");
const roleE = fixture("role-cross-account-trust.json");

describe("extractAccountIdFromArn", () => {
  it("extracts the 12-digit account ID from a role ARN", () => {
    expect(extractAccountIdFromArn(roleD.arn)).toBe(ACCOUNT);
  });

  it("returns null for non-IAM ARNs", () => {
    expect(extractAccountIdFromArn("arn:aws:s3:::my-bucket")).toBeNull();
  });
});

describe("parseTrustPolicy", () => {
  it("finds the wildcard principal on Role D", () => {
    const trust = parseTrustPolicy(roleD.assumeRolePolicyDocument, ACCOUNT);
    expect(trust.parseError).toBeUndefined();
    expect(trust.principals).toContain("*");
    expect(trust.externalAccounts).toEqual([]);
  });

  it("extracts external accounts on Role E", () => {
    const trust = parseTrustPolicy(roleE.assumeRolePolicyDocument, ACCOUNT);
    expect(trust.parseError).toBeUndefined();
    expect(trust.externalAccounts).toContain("999988887777");
    expect(trust.externalAccounts).toContain("555566667777");
    expect(trust.externalAccounts).toHaveLength(2);
  });

  it("does not report same-account principals as external", () => {
    const doc = encodeURIComponent(JSON.stringify({
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${ACCOUNT}:root` }, Action: "sts:AssumeRole" }],
    }));
    const trust = parseTrustPolicy(doc, ACCOUNT);
    expect(trust.externalAccounts).toEqual([]);
    expect(trust.principals).toEqual([`arn:aws:iam::${ACCOUNT}:root`]);
  });

  it("ignores Deny statements", () => {
    const doc = encodeURIComponent(JSON.stringify({
      Statement: [{ Effect: "Deny", Principal: "*", Action: "sts:AssumeRole" }],
    }));
    const trust = parseTrustPolicy(doc, ACCOUNT);
    expect(trust.principals).toEqual([]);
  });

  it("sets parseError on a malformed document instead of throwing", () => {
    const trust = parseTrustPolicy("this is not valid JSON {{{{", ACCOUNT);
    expect(trust.parseError).toContain("Could not parse trust policy");
    expect(trust.principals).toEqual([]);
  });

  it("returns empty results for an empty document", () => {
    const trust = parseTrustPolicy("", ACCOUNT);
    expect(trust.parseError).toBeUndefined();
    expect(trust.principals).toEqual([]);
  });
});
