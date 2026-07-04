// src/tools/generate-posture-report.ts

import { auditBedrockPosture } from "./audit-bedrock-posture.js";
import { findPromptInjectionSignals } from "./find-prompt-injection.js";
import { buildMarkdownReport } from "../report/markdown.js";
import { generateHtmlReport } from "../report/html.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { listAllRoles } from "../aws/iam.js";
import { extractAccountIdFromArn } from "../analysis/policy.js";
import { IAMClient } from "@aws-sdk/client-iam";
import type { BedrockSecurityFinding } from "../types.js";

interface GenerateReportInput {
  region?: string;
  title?: string;
  /** Optional: audit a single role only (CLI --role). Passed through to Tool 1. */
  roleName?: string;
  /** Optional: hours of CloudTrail/invocation history (CLI --hours). Passed through to Tool 2. */
  hoursBack?: number;
}

export interface PostureReportResult {
  markdown: string;
  htmlPath?: string;
  /** The raw findings the report was built from. Lets CLI/CI consumers compute
   * exit codes and emit JSON without re-running the tools. */
  findings: BedrockSecurityFinding[];
}

export async function generateAiPostureReport(
  input: GenerateReportInput,
  region: string
): Promise<PostureReportResult> {
  // ── 1. Collect all findings ────────────────────────────────
  const [iamFindings, injectionFindings] = await Promise.all([
    auditBedrockPosture({ roleName: input.roleName }, region),
    findPromptInjectionSignals({ hoursBack: input.hoursBack }, region),
  ]);
  const allFindings = [...iamFindings, ...injectionFindings];

  // ── 2. Resolve account ID from a role ARN (no sts:GetCallerIdentity) ──
  let accountId: string | undefined;
  try {
    const roles = await listAllRoles(new IAMClient({ region }));
    accountId = roles.length > 0 ? extractAccountIdFromArn(roles[0].arn) ?? undefined : undefined;
  } catch {
    // Non-fatal — the report falls back to "unknown".
  }

  // ── 3. Build markdown ──────────────────────────────────────
  const markdown = buildMarkdownReport(allFindings, {
    region,
    title: input.title,
    accountId,
  });

  // ── 4. Write self-contained HTML if an output dir is configured ──
  let htmlPath: string | undefined;
  const outputDir = process.env.BEDROCK_SECURITY_OUTPUT_DIR;
  if (outputDir) {
    const html = generateHtmlReport(allFindings, {
      accountId: accountId ?? process.env.BEDROCK_SECURITY_ACCOUNT_ID,
      region,
      title: input.title,
    });
    const filename = `bedrock-security-${new Date().toISOString().slice(0, 10)}.html`;
    // Ensure the output directory exists before writing (the CLI --out-dir may not exist yet).
    mkdirSync(outputDir, { recursive: true });
    htmlPath = `${outputDir}/${filename}`;
    writeFileSync(htmlPath, html, "utf-8");
  }

  return { markdown, htmlPath, findings: allFindings };
}
