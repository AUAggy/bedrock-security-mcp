// src/report/html.ts

import type { BedrockSecurityFinding } from "../types.js";
import { computePostureScore } from "./markdown.js";
import { getRuleMetadata } from "../rules/catalog.js";

/**
 * Generate a self-contained HTML security posture report.
 *
 * Design: a formal assessment document, not an app. White paper, serif
 * masthead under a thick-thin double rule, hairline dividers instead of
 * boxes, a print-safe severity palette, and severity rendered as small-caps
 * colored text rather than filled pills. ScoutSuite single-page pattern:
 * severity meter up top, collapsible finding entries, remediation roadmap,
 * compliance mapping. No external CSS, fonts, or JS dependencies beyond one
 * inline <script> for entry toggling.
 */

// Print-safe severity palette (deliberately not a CSS-framework default set).
// "low" is steel, not blue, so links stay the only blue-ish affordance.
const SEVERITY_COLOR: Record<string, string> = {
  critical: "#A82C21",
  high: "#B4560B",
  medium: "#8A6A05",
  low: "#4A5B6E",
};
const PASS_COLOR = "#2E6E4E";
const INK = "#1B1E23";

/** Human-readable labels for the framework tags the tool cites. */
const FRAMEWORK_LABELS: Record<string, string> = {
  "OWASP_LLM_TOP10:LLM01": "OWASP LLM01 · Prompt Injection",
  "OWASP_LLM_TOP10:LLM02": "OWASP LLM02 · Sensitive Information Disclosure",
  "OWASP_LLM_TOP10:LLM05": "OWASP LLM05 · Improper Output Handling",
  "OWASP_LLM_TOP10:LLM06": "OWASP LLM06 · Excessive Agency",
  "OWASP_LLM_TOP10:LLM07": "OWASP LLM07 · System Prompt Leakage",
  "OWASP_LLM_TOP10:LLM08": "OWASP LLM08 · Vector & Embedding Weaknesses",
  "OWASP_LLM_TOP10:LLM10": "OWASP LLM10 · Unbounded Consumption",
  "OWASP_AGENTIC:ASI01": "OWASP Agentic ASI01 · Goal Hijack",
  "OWASP_AGENTIC:ASI02": "OWASP Agentic ASI02 · Tool Misuse",
  "OWASP_AGENTIC:ASI03": "OWASP Agentic ASI03 · Identity & Privilege Abuse",
  "OWASP_AGENTIC:ASI04": "OWASP Agentic ASI04 · Supply Chain",
  "OWASP_AGENTIC:ASI05": "OWASP Agentic ASI05 · Unexpected Code Execution",
  "OWASP_AGENTIC:ASI07": "OWASP Agentic ASI07 · Insecure Inter-Agent Comms",
  "OWASP_AGENTIC:ASI08": "OWASP Agentic ASI08 · Cascading Failures",
  "NIST_AI_RMF": "NIST AI RMF 1.0",
  "MITRE_ATLAS": "MITRE ATLAS",
  "AWS_WA_ML:SEC-3": "AWS WA ML Lens SEC-3 · Identity & Access",
  "AWS_WA_ML:SEC-6": "AWS WA ML Lens SEC-6 · Data Protection",
  "AWS_WA_ML:SEC-10": "AWS WA ML Lens SEC-10 · Incident Response",
  "AWS_WA_ML:OPS-8": "AWS WA ML Lens OPS-8 · Monitoring",
};

export function frameworkLabel(tag: string): string {
  return FRAMEWORK_LABELS[tag] ?? tag;
}

export function generateHtmlReport(
  findings: BedrockSecurityFinding[],
  options: {
    accountId?: string;
    region?: string;
    title?: string;
  } = {}
): string {
  const accountId = options.accountId ?? "unknown";
  const region = options.region ?? "unknown";
  const title = options.title ?? "AWS Bedrock Security Posture Report";
  const generatedAt = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  // --- Compute summary statistics -------------------------------------------
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byStatus = { FAIL: 0, PASS: 0, ERROR: 0, NOT_APPLICABLE: 0 };
  const violations = findings.filter(f => f.status === "FAIL");
  const passed = findings.filter(f => f.status === "PASS");

  for (const f of findings) {
    if (f.severity in bySeverity) bySeverity[f.severity]++;
    if (f.status in byStatus) byStatus[f.status]++;
  }

  const violationCount = violations.length;
  const postureScore = computePostureScore(findings);

  const riskRating =
    bySeverity.critical > 0 ? "Critical" :
    bySeverity.high > 0 ? "High" :
    bySeverity.medium > 0 ? "Medium" :
    "Low";

  const riskColor =
    bySeverity.critical > 0 ? SEVERITY_COLOR.critical :
    bySeverity.high > 0 ? SEVERITY_COLOR.high :
    bySeverity.medium > 0 ? SEVERITY_COLOR.medium :
    PASS_COLOR;

  const sevColor = (s: string) => SEVERITY_COLOR[s] ?? "#5A5F66";
  const sevLabel = (s: string) =>
    `<span class="severity-label" style="color: ${sevColor(s)};">${s.toUpperCase()}</span>`;

  // --- Severity meter --------------------------------------------------------
  const barTotal = bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low;

  function severityBar(): string {
    if (barTotal === 0) {
      return `<div class="severity-bar">
        <div style="flex: 1; background: ${PASS_COLOR};" title="All checks passed"></div>
      </div>`;
    }
    const segments = [
      { count: bySeverity.critical, color: SEVERITY_COLOR.critical, label: "Critical" },
      { count: bySeverity.high, color: SEVERITY_COLOR.high, label: "High" },
      { count: bySeverity.medium, color: SEVERITY_COLOR.medium, label: "Medium" },
      { count: bySeverity.low, color: SEVERITY_COLOR.low, label: "Low" },
    ].filter(s => s.count > 0);

    return `<div class="severity-bar">
      ${segments.map(s =>
        `<div style="flex: ${s.count}; background: ${s.color};" title="${s.label}: ${s.count}"></div>`
      ).join("")}
    </div>`;
  }

  function barLegend(): string {
    const parts = (["critical", "high", "medium", "low"] as const).map(s => {
      const n = bySeverity[s];
      const color = n > 0 ? sevColor(s) : "#9BA0A6";
      return `<span style="color: ${color};">${n} ${s}</span>`;
    });
    return `<div class="bar-legend">${parts.join('<span class="legend-sep">·</span>')}</div>`;
  }

  // --- Figures row (replaces tinted stat cards) ------------------------------
  function figuresRow(): string {
    const items: Array<{ label: string; count: number; color: string }> = [
      { label: "Critical", count: bySeverity.critical, color: SEVERITY_COLOR.critical },
      { label: "High", count: bySeverity.high, color: SEVERITY_COLOR.high },
      { label: "Medium", count: bySeverity.medium, color: SEVERITY_COLOR.medium },
      { label: "Low", count: bySeverity.low, color: SEVERITY_COLOR.low },
      { label: "Errors", count: byStatus.ERROR, color: INK },
    ];
    return items.map(i =>
      `<div class="figure">
        <div class="figure-value" style="color: ${i.count > 0 ? i.color : "#B9BDC2"};">${i.count}</div>
        <div class="figure-label">${i.label}</div>
      </div>`
    ).join("");
  }

  // --- Compliance tags --------------------------------------------------------
  function frameworkTags(tags: string[]): string {
    return tags.map(cf => `<span class="tag">${escapeHtml(frameworkLabel(cf))}</span>`).join("");
  }

  // --- Finding entry ----------------------------------------------------------
  function findingCard(f: BedrockSecurityFinding, index: number): string {
    const color = sevColor(f.severity);
    const id = `finding-${f.severity}-${index}`;

    return `<div class="finding" style="border-left-color: ${color};">
      <button class="finding-header" aria-expanded="false" aria-controls="${id}">
        <div class="finding-title-row">
          ${sevLabel(f.severity)}
          <span class="finding-title">${escapeHtml(f.title)}</span>
        </div>
        <div class="finding-meta">
          <span class="rule-id">${escapeHtml(f.ruleId)}</span>
          <span class="chevron" aria-hidden="true">▸</span>
        </div>
      </button>
      <div class="finding-body" id="${id}">
        <div class="finding-detail">
          <div class="detail-label">Resource</div>
          <div class="detail-value mono">${escapeHtml(f.resource)}</div>
        </div>
        <div class="finding-detail">
          <div class="detail-label">Details</div>
          <div class="detail-value">${escapeHtml(f.details)}</div>
        </div>
        ${(() => {
          const meta = getRuleMetadata(f.ruleId);
          if (!meta) return "";
          return `<div class="finding-detail">
            <div class="detail-label">Threat</div>
            <div class="detail-value">${escapeHtml(meta.threat)}</div>
          </div>
          <div class="finding-detail">
            <div class="detail-label">Why this matters</div>
            <div class="detail-value">${escapeHtml(meta.rationale)}</div>
          </div>`;
        })()}
        <div class="finding-detail">
          <div class="detail-label">Remediation</div>
          <div class="detail-value"><pre>${escapeHtml(f.remediation)}</pre></div>
        </div>
        ${f.complianceFrameworks.length ? `<div class="finding-detail">
          <div class="detail-label">Compliance</div>
          <div class="detail-value">${frameworkTags(f.complianceFrameworks)}</div>
        </div>` : ""}
        ${f.reference ? `<div class="finding-detail">
          <div class="detail-label">Reference</div>
          <div class="detail-value"><a class="ref" href="${escapeHtml(f.reference)}" target="_blank" rel="noopener">${escapeHtml(f.reference)}</a></div>
        </div>` : ""}
      </div>
    </div>`;
  }

  // --- Finding section --------------------------------------------------------
  // cardIndex is call-scoped so entry IDs are globally unique across sections.
  let cardIndex = 0;
  function findingSection(severity: string, label: string, sectionFindings: BedrockSecurityFinding[]): string {
    if (sectionFindings.length === 0) return "";
    return `<section class="findings-section">
      <h2 class="section-heading">${label} (${sectionFindings.length})</h2>
      ${sectionFindings.map(f => findingCard(f, cardIndex++)).join("")}
    </section>`;
  }

  // --- Remediation roadmap table ----------------------------------------------
  function remediationTable(tableFindings: BedrockSecurityFinding[]): string {
    if (tableFindings.length === 0) return "";
    const rows = tableFindings.map(f => {
      const effort = f.severity === "critical" ? "Within 24 hours" :
                     f.severity === "high" ? "Within 3 days" :
                     f.severity === "medium" ? "Within 2 weeks" :
                     "Next sprint";
      return `<tr>
        <td>${sevLabel(f.severity)}</td>
        <td class="mono">${escapeHtml(f.ruleId)}</td>
        <td>${escapeHtml(f.title)}</td>
        <td class="nowrap">${effort}</td>
      </tr>`;
    }).join("");

    return `<section class="remediation-section">
      <h2 class="section-heading">Remediation roadmap</h2>
      <table class="roadmap-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>Issue</th>
            <th>Target</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </section>`;
  }

  // --- Compliance mapping table -------------------------------------------------
  function complianceTable(tableFindings: BedrockSecurityFinding[]): string {
    const map = new Map<string, Set<string>>();
    for (const f of tableFindings) {
      for (const cf of f.complianceFrameworks) {
        if (!map.has(cf)) map.set(cf, new Set());
        map.get(cf)!.add(f.ruleId);
      }
    }
    if (map.size === 0) return "";
    const rows = [...map.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([fw, rules]) =>
        `<tr><td class="framework-cell">${escapeHtml(frameworkLabel(fw))}</td><td>${[...rules].map(r => `<code>${escapeHtml(r)}</code>`).join(", ")}</td></tr>`
      ).join("");

    return `<section class="compliance-section">
      <h2 class="section-heading">Compliance mapping</h2>
      <table class="compliance-table">
        <thead><tr><th>Framework</th><th>Rules violated</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>`;
  }

  // --- Passed checks (compact) ---------------------------------------------------
  function passedSection(passedFindings: BedrockSecurityFinding[]): string {
    if (passedFindings.length === 0) return "";
    return `<section class="passed-section">
      <h2 class="section-heading">Passed checks (${passedFindings.length})</h2>
      <p class="passed-summary">${passedFindings.map(f => escapeHtml(f.title)).join("; ")}.</p>
    </section>`;
  }

  // --- Assemble the page ---------------------------------------------------------
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)} — ${escapeHtml(accountId)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --ink: ${INK};
    --ink-2: #55595F;
    --ink-3: #9BA0A6;
    --hairline: #E2E3E5;
    --panel: #F6F6F4;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    color: var(--ink);
    background: #FFFFFF;
    -webkit-font-smoothing: antialiased;
  }

  .serif {
    font-family: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, Cambria, "Times New Roman", serif;
  }

  .mono, code, pre, .rule-id, .bar-legend, .report-meta {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  }

  code {
    font-size: 12px;
    background: var(--panel);
    border: 1px solid var(--hairline);
    padding: 1px 5px;
  }

  pre {
    font-size: 12.5px;
    background: var(--panel);
    border: 1px solid var(--hairline);
    padding: 12px 14px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.55;
  }

  .page {
    max-width: 860px;
    margin: 0 auto;
    padding: 48px 40px 72px;
  }

  /* --- Masthead: serif title over a thick-thin double rule ----------------- */
  .eyebrow {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 11px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--ink-2);
    margin-bottom: 10px;
  }

  .masthead h1 {
    font-size: 30px;
    font-weight: 600;
    letter-spacing: -0.01em;
    line-height: 1.25;
    margin-bottom: 18px;
  }

  .rule-double {
    height: 6px;
    border-top: 3px solid var(--ink);
    border-bottom: 1px solid var(--ink);
    margin-bottom: 14px;
  }

  .report-meta {
    font-size: 12px;
    color: var(--ink-2);
    display: flex;
    gap: 8px 24px;
    flex-wrap: wrap;
  }

  .report-meta strong { color: var(--ink); font-weight: 600; }

  .scope-line {
    font-size: 12px;
    color: var(--ink-3);
    margin-top: 6px;
  }

  /* --- Overview -------------------------------------------------------------- */
  .overview {
    margin-top: 40px;
    padding-top: 24px;
    border-top: 1px solid var(--hairline);
  }

  .overview-grid {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 32px;
    flex-wrap: wrap;
  }

  .risk-rating {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 650;
    margin-bottom: 6px;
  }

  .health-score {
    font-size: 52px;
    font-weight: 650;
    letter-spacing: -0.02em;
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }

  .health-score .denom {
    font-size: 17px;
    font-weight: 500;
    color: var(--ink-3);
  }

  .health-label {
    font-size: 12px;
    color: var(--ink-2);
    margin-top: 6px;
  }

  .figures {
    display: flex;
  }

  .figure {
    padding: 0 22px;
    border-left: 1px solid var(--hairline);
    text-align: right;
  }

  .figure:last-child { padding-right: 0; }

  .figure-value {
    font-size: 26px;
    font-weight: 650;
    line-height: 1.1;
    font-variant-numeric: tabular-nums;
  }

  .figure-label {
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
    color: var(--ink-2);
    margin-top: 2px;
  }

  .severity-bar {
    display: flex;
    gap: 1px;
    height: 10px;
    margin-top: 24px;
    background: var(--hairline);
    border: 1px solid var(--hairline);
  }

  .severity-bar > div { min-height: 8px; }

  .bar-legend {
    font-size: 11px;
    margin-top: 8px;
    color: var(--ink-3);
  }

  .legend-sep { color: var(--ink-3); padding: 0 8px; }

  /* --- Sections ---------------------------------------------------------------- */
  main { margin-top: 44px; }

  .section-heading {
    font-size: 12px;
    font-weight: 650;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--ink);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--ink);
    margin-bottom: 0;
  }

  .findings-section,
  .remediation-section,
  .compliance-section,
  .passed-section {
    margin-bottom: 48px;
  }

  .remediation-section .section-heading,
  .compliance-section .section-heading,
  .passed-section .section-heading {
    margin-bottom: 0;
  }

  /* --- Severity labels ----------------------------------------------------------- */
  .severity-label {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.09em;
    white-space: nowrap;
    flex-shrink: 0;
    min-width: 62px;
  }

  /* --- Finding entries: hairline list, 2px severity rule at left ------------------ */
  .finding {
    border-bottom: 1px solid var(--hairline);
    border-left: 2px solid transparent;
  }

  .finding-header {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 13px 2px 13px 14px;
    background: none;
    border: none;
    cursor: pointer;
    text-align: left;
    font: inherit;
    color: inherit;
    gap: 16px;
  }

  .finding-header:hover { background: var(--panel); }
  .finding-header:focus-visible { outline: 2px solid var(--ink); outline-offset: -2px; }

  .finding-title-row {
    display: flex;
    align-items: baseline;
    gap: 14px;
    min-width: 0;
    flex: 1;
  }

  .finding-title {
    font-size: 13.5px;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .finding-meta {
    display: flex;
    align-items: baseline;
    gap: 14px;
    flex-shrink: 0;
  }

  .rule-id { font-size: 11px; color: var(--ink-3); }

  .chevron {
    color: var(--ink-3);
    font-size: 11px;
    transition: transform 0.15s ease;
    display: inline-block;
  }

  .finding-body {
    display: none;
    padding: 6px 2px 20px 14px;
  }

  .finding-body.open { display: block; }

  .finding-detail {
    display: grid;
    grid-template-columns: 128px 1fr;
    gap: 16px;
    padding: 7px 0;
  }

  .detail-label {
    font-size: 10.5px;
    font-weight: 650;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--ink-2);
    padding-top: 2px;
  }

  .detail-value { font-size: 13px; color: var(--ink); min-width: 0; }
  .detail-value.mono { font-size: 12px; word-break: break-all; }

  .tag {
    display: inline-block;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 10.5px;
    color: var(--ink-2);
    border: 1px solid var(--hairline);
    padding: 2px 7px;
    margin: 0 6px 6px 0;
  }

  a { color: var(--ink); text-decoration: underline; text-underline-offset: 2px; text-decoration-color: var(--ink-3); }
  a:hover { text-decoration-color: var(--ink); }
  .ref { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11.5px; color: var(--ink-2); word-break: break-all; }

  /* --- Tables ------------------------------------------------------------------- */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
  }

  th {
    text-align: left;
    font-size: 10.5px;
    font-weight: 650;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--ink-2);
    padding: 10px 14px 8px 0;
    border-bottom: 1px solid var(--hairline);
  }

  td {
    padding: 9px 14px 9px 0;
    border-bottom: 1px solid var(--hairline);
    vertical-align: top;
  }

  td.mono { font-size: 11.5px; color: var(--ink-2); }
  td.nowrap { white-space: nowrap; }
  .framework-cell { font-weight: 500; white-space: nowrap; }

  /* --- Passed checks --------------------------------------------------------------- */
  .passed-summary {
    font-size: 13px;
    color: var(--ink-2);
    border-bottom: 1px solid var(--hairline);
    padding: 14px 0;
    line-height: 1.7;
  }
  .passed-section .section-heading { border-bottom-color: ${PASS_COLOR}; }

  /* --- Footer ------------------------------------------------------------------------ */
  .report-footer {
    border-top: 1px solid var(--ink);
    margin-top: 8px;
    padding-top: 14px;
    font-size: 11px;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    color: var(--ink-3);
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px 24px;
  }

  /* --- Small screens ------------------------------------------------------------------- */
  @media (max-width: 640px) {
    .page { padding: 32px 20px 56px; }
    .figures { width: 100%; }
    .figure { flex: 1; padding: 0 10px; text-align: left; }
    .figure:first-child { border-left: none; padding-left: 0; }
    .finding-detail { grid-template-columns: 1fr; gap: 3px; }
    .finding-meta .rule-id { display: none; }
  }

  /* --- Motion ----------------------------------------------------------------------------- */
  @media (prefers-reduced-motion: reduce) {
    .chevron { transition: none; }
  }

  /* --- Print ------------------------------------------------------------------------------- */
  @media print {
    .page { padding: 0; max-width: none; }
    .finding-body { display: block !important; }
    .finding-header { cursor: default; }
    .chevron { display: none; }
    .finding, table, tr { break-inside: avoid; }
  }
</style>
</head>
<body>

<div class="page">

<header class="masthead">
  <p class="eyebrow">Security assessment · bedrock-security-mcp</p>
  <h1 class="serif">${escapeHtml(title)}</h1>
  <div class="rule-double"></div>
  <div class="report-meta">
    <span>Account <strong>${escapeHtml(accountId)}</strong></span>
    <span>Region <strong>${escapeHtml(region)}</strong></span>
    <span>Generated <strong>${generatedAt}</strong></span>
  </div>
  <p class="scope-line">Assessed against OWASP LLM Top 10 (2025), OWASP Agentic Applications Top 10, NIST AI RMF, MITRE ATLAS.</p>
</header>

<section class="overview">
  <div class="overview-grid">
    <div>
      <div class="risk-rating" style="color: ${riskColor};">Overall risk: ${riskRating}</div>
      <div class="health-score" style="color: ${riskColor};">${postureScore}<span class="denom">/100</span></div>
      <div class="health-label">Posture score · ${violationCount} violation(s), ${byStatus.ERROR} error(s)</div>
    </div>
    <div class="figures">
      ${figuresRow()}
    </div>
  </div>
  ${severityBar()}
  ${barLegend()}
</section>

<main>
  ${findingSection("critical", "Critical", violations.filter(f => f.severity === "critical"))}
  ${findingSection("high", "High", violations.filter(f => f.severity === "high"))}
  ${findingSection("medium", "Medium", violations.filter(f => f.severity === "medium"))}
  ${findingSection("low", "Low", violations.filter(f => f.severity === "low"))}
  ${remediationTable(violations)}
  ${complianceTable(violations)}
  ${passedSection(passed)}
</main>

<footer class="report-footer">
  <span>Generated by bedrock-security-mcp v0.1.0</span>
  <span>OWASP LLM Top 10 (2025), OWASP Agentic Applications Top 10, NIST AI RMF, MITRE ATLAS</span>
</footer>

</div>

<script>
  document.querySelectorAll('.finding-header').forEach(header => {
    header.addEventListener('click', function() {
      const body = this.nextElementSibling;
      const expanded = body.classList.toggle('open');
      this.setAttribute('aria-expanded', expanded);
      const chevron = this.querySelector('.chevron');
      if (chevron) chevron.style.transform = expanded ? 'rotate(90deg)' : '';
    });
  });
</script>

</body>
</html>`;
}

function escapeHtml(text: string): string {
  const map: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" };
  return text.replace(/[&<>"']/g, c => map[c] ?? c);
}
