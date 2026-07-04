import { describe, it, expect } from "vitest";
import { ruleRegistry } from "../src/rules/registry.js";
import "../src/rules/bedrock-rules.js";

function rule(ruleId: string) {
  const spec = ruleRegistry.get(ruleId);
  expect(spec, `rule ${ruleId} must be registered`).toBeDefined();
  return spec!;
}

const strongGuardrail = {
  guardrailId: "gr-strong",
  guardrailArn: "arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-strong",
  name: "Guardrail-Strong",
  version: "1",
  contentFilters: [
    { type: "PROMPT_ATTACK", inputStrength: "HIGH", outputStrength: "HIGH" },
    { type: "HATE", inputStrength: "HIGH", outputStrength: "HIGH" },
  ],
  hasPromptAttackFilter: true,
  minContentStrength: "HIGH",
  piiEntityCount: 3,
  deniedTopicCount: 1,
  hasGrounding: true,
};

const weakGuardrail = {
  ...strongGuardrail,
  guardrailId: "gr-weak",
  guardrailArn: "arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-weak",
  name: "Guardrail-Weak",
  contentFilters: [{ type: "HATE", inputStrength: "LOW", outputStrength: "LOW" }],
  hasPromptAttackFilter: false,
  minContentStrength: "LOW",
  piiEntityCount: 0,
  deniedTopicCount: 0,
  hasGrounding: false,
};

describe("bedrock-logging-disabled", () => {
  it("fires high when logging is off", () => {
    const f = rule("bedrock-logging-disabled").check({ loggingEnabled: false, region: "global" });
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("high");
    expect(f!.complianceFrameworks).toContain("AWS_WA_ML:SEC-10");
    expect(f!.complianceFrameworks).toContain("MITRE_ATLAS");
  });

  it("is suppressed when logging is on", () => {
    expect(rule("bedrock-logging-disabled").check({ loggingEnabled: true, region: "global" })).toBeNull();
  });
});

describe("invocation-logs-without-cmk", () => {
  it("fires medium when a CloudWatch log group has no kmsKeyId", () => {
    const f = rule("invocation-logs-without-cmk").check({
      loggingEnabled: true, logGroupName: "/aws/bedrock/model-invocations", kmsKeyId: undefined, region: "global",
    });
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("medium");
    expect(f!.details).toContain("/aws/bedrock/model-invocations");
    expect(f!.complianceFrameworks).toContain("AWS_WA_ML:SEC-6");
  });

  it("is suppressed when a CMK is associated", () => {
    const f = rule("invocation-logs-without-cmk").check({
      loggingEnabled: true, logGroupName: "/aws/bedrock/model-invocations",
      kmsKeyId: "arn:aws:kms:us-east-1:111122223333:key/abc", region: "global",
    });
    expect(f).toBeNull();
  });

  it("is not applicable when no CloudWatch log group is configured", () => {
    // bedrock-logging-disabled covers the logging-off case; this rule stays quiet.
    expect(rule("invocation-logs-without-cmk").check({ loggingEnabled: false, region: "global" })).toBeNull();
  });
});

describe("guardrail-content-filter-weak", () => {
  it("fires high on a LOW-strength guardrail with no PROMPT_ATTACK filter", () => {
    const f = rule("guardrail-content-filter-weak").check({ config: weakGuardrail, region: "global" });
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("high");
    expect(f!.details).toContain("NO PROMPT_ATTACK filter");
    expect(f!.details).toContain("LOW");
  });

  it("fires when PROMPT_ATTACK exists but strength is below HIGH", () => {
    const cfg = {
      ...strongGuardrail,
      contentFilters: [{ type: "PROMPT_ATTACK", inputStrength: "MEDIUM", outputStrength: "HIGH" }],
      minContentStrength: "MEDIUM",
    };
    const f = rule("guardrail-content-filter-weak").check({ config: cfg, region: "global" });
    expect(f).not.toBeNull();
  });

  it("is suppressed on the strong guardrail", () => {
    expect(rule("guardrail-content-filter-weak").check({ config: strongGuardrail, region: "global" })).toBeNull();
  });
});

describe("guardrail-no-pii-filter", () => {
  it("fires medium when no PII entities are configured and cites OWASP LLM02", () => {
    const f = rule("guardrail-no-pii-filter").check({ config: weakGuardrail, region: "global" });
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("medium");
    expect(f!.complianceFrameworks).toContain("OWASP_LLM_TOP10:LLM02");
  });

  it("is suppressed when PII entities exist", () => {
    expect(rule("guardrail-no-pii-filter").check({ config: strongGuardrail, region: "global" })).toBeNull();
  });
});

describe("guardrail-no-denied-topics", () => {
  it("fires low on an empty denied-topics list", () => {
    const f = rule("guardrail-no-denied-topics").check({ config: weakGuardrail, region: "global" });
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("low");
  });

  it("is suppressed when topics are denied", () => {
    expect(rule("guardrail-no-denied-topics").check({ config: strongGuardrail, region: "global" })).toBeNull();
  });
});

describe("guardrail-grounding-disabled", () => {
  it("fires low when grounding is not configured", () => {
    const f = rule("guardrail-grounding-disabled").check({ config: weakGuardrail, region: "global" });
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("low");
  });

  it("is suppressed when grounding is enabled", () => {
    expect(rule("guardrail-grounding-disabled").check({ config: strongGuardrail, region: "global" })).toBeNull();
  });
});

describe("fully configured account", () => {
  it("produces zero guardrail findings for the strong guardrail via evaluate()", () => {
    const findings = ruleRegistry.evaluate([
      { scope: "bedrock_guardrail", data: { config: strongGuardrail, region: "global" } },
      { scope: "bedrock_config", data: { loggingEnabled: true, logGroupName: "/aws/bedrock/x", kmsKeyId: "arn:aws:kms:::key/1", region: "global" } },
    ]);
    expect(findings).toEqual([]);
  });
});
