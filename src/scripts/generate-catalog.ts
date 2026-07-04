// src/scripts/generate-catalog.ts
//
// Writes examples/rules-catalog.json from allRuleMetadata() (ScoutSuite
// findings.json pattern). Run via `npm run build:catalog` after `npm run build`.
// The JSON artifact is generated — never hand-edited.

import { allRuleMetadata } from "../rules/catalog.js";
import { writeFileSync } from "node:fs";

const catalog = {
  $schema: "https://example.com/bedrock-security-mcp/rules-catalog-v1.json",
  generatedBy: "bedrock-security-mcp — run `npm run build:catalog` to regenerate from src/rules/catalog.ts",
  note: "Single source of truth is src/rules (RuleSpec.threat/rationale + DETECTION_RULE_METADATA). This file is a generated artifact; do not edit by hand.",
  rules: allRuleMetadata().map(r => ({
    ruleId: r.ruleId,
    title: r.title,
    severity: r.severity,
    appliesTo: r.appliesTo,
    complianceFrameworks: r.complianceFrameworks,
    threat: r.threat,
    rationale: r.rationale,
  })),
};

writeFileSync("examples/rules-catalog.json", JSON.stringify(catalog, null, 2) + "\n", "utf-8");
console.log(`Wrote ${catalog.rules.length} rule entries to examples/rules-catalog.json`);
