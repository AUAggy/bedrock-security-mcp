// src/report/markdown.ts

import type { BedrockSecurityFinding } from "../types.js";
import { getRuleMetadata } from "../rules/catalog.js";

/**
 * Posture score: a violation-weighted 0-100 score, NOT a pass-rate.
 *
 * The previous design computed passed/total, but the tools only emit findings
 * for violations (no per-check PASS), so a pass-rate was meaningless and a
 * single synthetic "no signals" PASS finding could inflate the score to 100%.
 * This weighted formula is honest about what it measures and needs no synthetic
 * findings. Weights mirror AWS Security Hub posture scoring: a single critical
 * finding caps the score at 75; four criticals floor it at 0.
 */
export function computePostureScore(findings: BedrockSecurityFinding[]): number {
  const weight = { critical: 25, high: 10, medium: 3, low: 1 };
  const deductions = findings
    .filter(f => f.status === "FAIL")
    .reduce((sum, f) => sum + (weight[f.severity] ?? 0), 0);
  return Math.max(0, 100 - deductions);
}

export interface MarkdownReportOptions {
  region: string;
  title?: string;
  accountId?: string;
}

/** Executive-summary category for a finding. Uses the catalog's appliesTo scope
 * (authoritative for all 17 rules); substring fallback covers synthetic
 * ERROR/PASS ruleIds that are not catalog entries (policy-parse-error,
 * iam-enumeration-error, guardrail-read-error, no-injection-signals, invalid-input). */
export function categorizeFinding(ruleId: string): string {
  const meta = getRuleMetadata(ruleId);
  switch (meta?.appliesTo) {
    case "iam_statement":
    case "iam_role":
      return "IAM & Access";
    case "invocation_log":
    case "cloudtrail_event":
    case "cloudtrail_config":
      return "Prompt Injection";
    case "bedrock_config":
    case "bedrock_guardrail":
      return "Bedrock Configuration";
  }
  if (/iam|policy|role|principal/.test(ruleId)) return "IAM & Access";
  if (/injection|prompt|token|hours|invalid-input/.test(ruleId)) return "Prompt Injection";
  return "Bedrock Configuration";
}

export function buildMarkdownReport(
  findings: BedrockSecurityFinding[],
  opts: MarkdownReportOptions
): string {
  const title = opts.title ?? "AWS AI/ML Workload Security Posture Report";

  // ── Summary statistics ─────────────────────────────────────
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byStatus = { FAIL: 0, PASS: 0, ERROR: 0, NOT_APPLICABLE: 0 };
  const byCategory = new Map<string, BedrockSecurityFinding[]>();

  for (const f of findings) {
    bySeverity[f.severity]++;
    byStatus[f.status]++;
    const category = categorizeFinding(f.ruleId);
    if (!byCategory.has(category)) byCategory.set(category, []);
    byCategory.get(category)!.push(f);
  }

  const violations = findings.filter(f => f.status === "FAIL");
  const violationCount = violations.length;
  const postureScore = computePostureScore(findings);

  // ── Build markdown ─────────────────────────────────────────
  const lines: string[] = [];

  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`**Generated:** ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC`);
  lines.push(`**Account:** ${opts.accountId ?? "unknown"}`);
  lines.push(`**Region:** ${opts.region}`);
  lines.push(`**Posture score:** ${postureScore}/100 | **Violations:** ${violationCount} | **Errors:** ${byStatus.ERROR}`);
  lines.push("");

  // Executive summary
  lines.push("## Executive Summary");
  lines.push("");
  const riskRating = bySeverity.critical > 0 ? "CRITICAL" :
                     bySeverity.high > 0 ? "HIGH" :
                     bySeverity.medium > 0 ? "MEDIUM" :
                     "LOW";
  lines.push(`**Overall Risk Rating:** ${riskRating}`);
  lines.push("");
  if (violationCount === 0) {
    lines.push("No security violations detected. Posture is clean across all evaluated controls.");
  } else {
    lines.push(`Found **${violationCount} security violation(s)** across ${byCategory.size} categor(ies):`);
    lines.push("");
    for (const [category, cats] of byCategory) {
      const fails = cats.filter(f => f.status === "FAIL").length;
      if (fails > 0) lines.push(`- **${category}:** ${fails} issue(s)`);
    }
    lines.push("");
    lines.push("> Address critical and high-severity findings within 24 hours. Medium findings within 7 days. Low findings during the next sprint.");
  }
  lines.push("");

  // Severity breakdown
  lines.push("## Severity Breakdown");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  lines.push(`| Critical | ${bySeverity.critical} |`);
  lines.push(`| High     | ${bySeverity.high} |`);
  lines.push(`| Medium   | ${bySeverity.medium} |`);
  lines.push(`| Low      | ${bySeverity.low} |`);
  lines.push("");

  // Critical findings (full detail)
  const criticals = violations.filter(f => f.severity === "critical");
  if (criticals.length > 0) {
    lines.push("## Critical Findings");
    lines.push("");
    for (const f of criticals) {
      lines.push(`### ${f.title}`);
      lines.push("");
      lines.push(`- **Rule:** \`${f.ruleId}\``);
      lines.push(`- **Resource:** \`${f.resource}\``);
      lines.push(`- **Compliance:** ${f.complianceFrameworks.join(", ")}`);
      const meta = getRuleMetadata(f.ruleId);
      if (meta) {
        lines.push("");
        lines.push(`**Threat:** ${meta.threat}`);
        lines.push("");
        lines.push(`**Why it matters:** ${meta.rationale}`);
      }
      lines.push("");
      lines.push(f.details);
      lines.push("");
      lines.push("**Remediation:**");
      lines.push("");
      lines.push(f.remediation);
      lines.push("");
      if (f.reference) {
        lines.push(`[Reference](${f.reference})`);
        lines.push("");
      }
      lines.push("---");
      lines.push("");
    }
  }

  // High findings (full detail)
  const highs = violations.filter(f => f.severity === "high");
  if (highs.length > 0) {
    lines.push("## High Findings");
    lines.push("");
    for (const f of highs) {
      lines.push(`### ${f.title}`);
      lines.push("");
      lines.push(`- **Rule:** \`${f.ruleId}\` | **Compliance:** ${f.complianceFrameworks.join(", ")}`);
      const meta = getRuleMetadata(f.ruleId);
      if (meta) {
        lines.push("");
        lines.push(`**Threat:** ${meta.threat}`);
        lines.push("");
        lines.push(`**Why it matters:** ${meta.rationale}`);
      }
      lines.push("");
      lines.push(f.details);
      lines.push("");
      lines.push(`**Fix:** ${f.remediation.split("\n")[0]}`);
      lines.push("");
    }
  }

  // Medium & Low (compact table)
  const others = violations.filter(f => f.severity !== "critical" && f.severity !== "high");
  if (others.length > 0) {
    lines.push("## Other Findings");
    lines.push("");
    lines.push("| Severity | Rule | Resource | Summary |");
    lines.push("|----------|------|----------|---------|");
    for (const f of others) {
      const summary = f.details.replace(/\|/g, "\\|").slice(0, 100);
      lines.push(`| ${f.severity} | \`${f.ruleId}\` | \`${f.resource.slice(0, 50)}\` | ${summary} |`);
    }
    lines.push("");
  }

  // Remediation roadmap
  lines.push("## Remediation Roadmap");
  lines.push("");
  lines.push("| Priority | Rule | Effort | Action |");
  lines.push("|----------|------|--------|--------|");
  for (const f of violations) {
    const effort = f.severity === "critical" ? "< 1 hour" :
                   f.severity === "high" ? "< 1 day" :
                   f.severity === "medium" ? "< 1 week" : "Next sprint";
    lines.push(`| ${f.severity.toUpperCase()} | \`${f.ruleId}\` | ${effort} | ${f.title} |`);
  }
  lines.push("");

  // Compliance mapping
  lines.push("## Compliance Mapping");
  lines.push("");
  const frameworks = new Map<string, string[]>();
  for (const f of violations) {
    for (const cf of f.complianceFrameworks) {
      if (!frameworks.has(cf)) frameworks.set(cf, []);
      frameworks.get(cf)!.push(f.ruleId);
    }
  }
  lines.push("| Framework | Violated Rules |");
  lines.push("|-----------|----------------|");
  for (const [fw, rules] of [...frameworks.entries()].sort()) {
    lines.push(`| ${fw} | ${[...new Set(rules)].map(r => `\`${r}\``).join(", ")} |`);
  }
  lines.push("");

  // Posture score
  lines.push("## Posture Score");
  lines.push("");
  lines.push(`**${postureScore}/100**`);
  lines.push("");
  lines.push("Score = 100 minus weighted violations (critical: 25, high: 10, medium: 3, low: 1). A clean account scores 100; a single critical finding caps the score at 75.");
  lines.push("");

  // Footer
  lines.push("---");
  lines.push("");
  lines.push("*Report generated by [bedrock-security-mcp](https://github.com/AUAggy/bedrock-security-mcp) — an opinionated MCP server for AWS AI/ML workload security.*");
  lines.push("");
  lines.push("**Frameworks referenced:** OWASP LLM Top 10 (2025), OWASP Agentic Applications Top 10, NIST AI RMF, MITRE ATLAS");

  return lines.join("\n");
}
