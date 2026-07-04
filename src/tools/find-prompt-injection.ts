// src/tools/find-prompt-injection.ts

import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { BedrockClient, GetModelInvocationLoggingConfigurationCommand } from "@aws-sdk/client-bedrock";
import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { lookupBedrockEvents } from "../aws/cloudtrail.js";
import { readInvocationLogs } from "../aws/cloudwatch-logs.js";
import { INJECTION_SIGNATURES, DEFAULT_TOKEN_THRESHOLD, isOffHours } from "../signatures.js";
import { OWASP_LLM_TOP10, OWASP_AGENTIC, MITRE_ATLAS } from "../compliance.js";
import type { BedrockSecurityFinding, PromptInjectionSignal } from "../types.js";

interface FindPromptInjectionInput {
  hoursBack?: number;        // How far back to scan (default: 24h, clamped to [1, 2160h] = 90d, CloudTrail's retention cap)
  maxEvents?: number;        // Max events to analyze per source (default: 100, clamped to [1, 1000])
  tokenThreshold?: number;   // Override the excessive-tokens threshold (default: 100000)
  region?: string;
}

// Per-signature compliance mapping. system-prompt-leak additionally cites
// LLM07 (System Prompt Leakage); the others cite LLM01 (Prompt Injection).
const SIGNATURE_COMPLIANCE: Record<string, string[]> = {
  "ignore-previous-instructions": [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_AGENTIC.ASI01_GOAL_HIJACK, MITRE_ATLAS],
  "system-prompt-leak":           [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_LLM_TOP10.LLM07_SYSTEM_PROMPT_LEAK, OWASP_AGENTIC.ASI01_GOAL_HIJACK, MITRE_ATLAS],
  "roleplay-jailbreak":           [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_AGENTIC.ASI01_GOAL_HIJACK, MITRE_ATLAS],
  "token-smuggling":              [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_LLM_TOP10.LLM02_SENSITIVE_INFO, MITRE_ATLAS],
};

/** Clamp and validate numeric inputs. Returns a clean config or an ERROR finding. */
function resolveInput(
  input: FindPromptInjectionInput
): { hoursBack: number; maxEvents: number; tokenThreshold: number; error?: BedrockSecurityFinding } {
  const rawHours = input.hoursBack ?? 24;
  const rawMax = input.maxEvents ?? 100;
  const rawTokens = input.tokenThreshold ?? DEFAULT_TOKEN_THRESHOLD;

  const err = (msg: string): BedrockSecurityFinding => ({
    findingId: "prompt-injection-input-error",
    ruleId: "invalid-input",
    title: "Invalid input to find_prompt_injection_signals",
    severity: "low",
    status: "ERROR",
    resource: "tool-input",
    region: "global",
    details: msg,
    remediation: "Provide numeric hoursBack in [1, 2160] (90 days), maxEvents in [1, 1000].",
    complianceFrameworks: [],
  });

  if (typeof rawHours !== "number" || !Number.isFinite(rawHours)) return { hoursBack: 24, maxEvents: 100, tokenThreshold: DEFAULT_TOKEN_THRESHOLD, error: err(`hoursBack must be a number, received: ${JSON.stringify(rawHours)}`) };
  if (typeof rawMax !== "number" || !Number.isFinite(rawMax)) return { hoursBack: 24, maxEvents: 100, tokenThreshold: DEFAULT_TOKEN_THRESHOLD, error: err(`maxEvents must be a number, received: ${JSON.stringify(rawMax)}`) };

  return {
    hoursBack: Math.min(Math.max(rawHours, 1), 2160),  // 2160h = 90d (CloudTrail LookupEvents retention cap)
    maxEvents: Math.min(Math.max(Math.floor(rawMax), 1), 1000),
    tokenThreshold: rawTokens > 0 ? rawTokens : DEFAULT_TOKEN_THRESHOLD,
  };
}

/**
 * Detect prompt-injection signals in Bedrock usage.
 *
 * Two data sources, both required for full coverage:
 * 1. CloudTrail LookupEvents — InvokeModel metadata. Drives off-hours and
 *    per-principal volume anomaly detection (this works off metadata alone).
 * 2. CloudWatch Logs (Bedrock model-invocation logging) — the actual prompt
 *    bodies. Drives regex signature matching and the real token-count check.
 *    Only available when logging is enabled with a CloudWatch destination.
 *    When logging is off, Tool 1's `bedrock-logging-disabled` finding already
 *    fires; this tool emits a NOT_APPLICABLE so the user knows the content
 *    scan did not run.
 */
export async function findPromptInjectionSignals(
  input: FindPromptInjectionInput,
  region: string
): Promise<BedrockSecurityFinding[]> {
  const cfg = resolveInput(input);
  if (cfg.error) return [cfg.error];
  const { hoursBack, maxEvents, tokenThreshold } = cfg;

  const cloudtrail = new CloudTrailClient({ region });
  const bedrock = new BedrockClient({ region });
  const logs = new CloudWatchLogsClient({ region });

  const findings: BedrockSecurityFinding[] = [];
  const signals: PromptInjectionSignal[] = [];
  const offHoursCounts = new Map<string, number>(); // principal → off-hours count

  // ── 1. CloudTrail metadata: trail-enabled check + off-hours/volume + guardrail-less ──
  // Hardening: if no trail is logging management events in this region, the
  // off-hours/volume/guardrail-less checks cannot run. Emit a NOT_APPLICABLE so the
  // user does NOT see a false "no signals detected" clean bill. The CloudWatch
  // Logs content scan still runs independently below.
  let cloudtrailManagementEnabled = true;
  try {
    const trails = await cloudtrail.send(new DescribeTrailsCommand({}));
    const trailList = trails.trailList ?? [];
    if (trailList.length === 0) {
      cloudtrailManagementEnabled = false;
      findings.push({
        findingId: "prompt-scan-cloudtrail-disabled",
        ruleId: "cloudtrail-management-disabled",
        title: "CloudTrail management-event logging is not enabled",
        severity: "medium",
        status: "NOT_APPLICABLE",
        resource: "cloudtrail:management-events",
        region,
        details: `No active CloudTrail trail was found in ${region}. Off-hours, per-principal volume, and guardrail-less-invocation detection require CloudTrail management events and were skipped. The CloudWatch Logs content scan (if model-invocation logging is enabled) still ran.`,
        remediation: "Enable a CloudTrail trail recording management events in this region. Without it, InvokeModel metadata is not captured and several detection checks cannot run.",
        complianceFrameworks: ["NIST_AI_RMF", MITRE_ATLAS],
      });
    }
  } catch {
    // Non-fatal: assume enabled and proceed; the lookup below will surface empty
    // results if CloudTrail is genuinely off.
  }

  // Per-principal count of invocations made WITHOUT a guardrail attached.
  // This is the detection-layer 'guardrail attachment' check — it fires at the
  // invocation layer where attachment actually matters, rather than guessing from
  // config. Deduped by event ID across CloudTrail + CloudWatch Logs sources.
  const guardlessCounts = new Map<string, number>();
  const seenGuardless = new Set<string>();
  const recordGuardless = (principal: string, key: string) => {
    if (seenGuardless.has(key)) return;
    seenGuardless.add(key);
    guardlessCounts.set(principal, (guardlessCounts.get(principal) ?? 0) + 1);
  };

  let events: any[] = [];
  if (cloudtrailManagementEnabled) {
    try {
      events = await lookupBedrockEvents(cloudtrail, hoursBack, maxEvents);
    } catch (err) {
      findings.push({
        findingId: "prompt-scan-cloudtrail-lookup-error",
        ruleId: "cloudtrail-management-disabled",
        title: "Could not look up Bedrock CloudTrail events",
        severity: "low",
        status: "ERROR",
        resource: "cloudtrail:management-events",
        region,
        details: `Failed to call LookupEvents: ${(err as Error).message}`,
        remediation: "Verify IAM permissions: cloudtrail:LookupEvents. Off-hours and guardrail-less detection from CloudTrail metadata was skipped.",
        complianceFrameworks: ["NIST_AI_RMF", MITRE_ATLAS],
      });
    }
  }
  let trailEventCount = 0;
  for (const event of events) {
    const eventName = event.EventName ?? "";
    if (!eventName.startsWith("InvokeModel")) continue;
    trailEventCount++;
    let cloudTrailEvent: any = {};
    try {
      cloudTrailEvent = JSON.parse(event.CloudTrailEvent ?? "{}");
    } catch {
      /* malformed event body — metadata-only handling below */
    }
    const requestParameters = cloudTrailEvent.requestParameters ?? {};
    const eventTime = event.EventTime ? new Date(event.EventTime) : new Date();
    const principal = event.Username ?? cloudTrailEvent.userIdentity?.arn ?? "unknown";

    // Guardrail-less invocation detection (CloudTrail source).
    if (!requestParameters.guardrail && !requestParameters.guardrailId) {
      recordGuardless(principal, `ct:${event.EventId ?? `${principal}-${eventTime.getTime()}`}`);
    }

    if (isOffHours(eventTime)) {
      const count = (offHoursCounts.get(principal) ?? 0) + 1;
      offHoursCounts.set(principal, count);
      if (count > 3) {
        findings.push({
          findingId: `off-hours-bedrock-${principal.replace(/[^a-zA-Z0-9]/g, "-")}-${Math.floor(eventTime.getTime() / 1000)}`,
          ruleId: "off-hours-bedrock-usage",
          title: `Off-hours Bedrock usage spike: ${principal}`,
          severity: "medium",
          status: "FAIL",
          resource: principal,
          region,
          details: `Principal ${principal} has ${count} Bedrock invocations during off-hours (UTC 22:00-06:00 or weekend). Most recent event: ${eventTime.toISOString()}. This may indicate automated malicious activity or a misconfigured batch job. Note: off-hours is defined in UTC; tune to your workload's geography.`,
          remediation: "1. Verify the off-hours usage is authorized. 2. If unauthorized, rotate credentials and investigate the calling application. 3. Consider IAM condition keys to restrict Bedrock invocation by time-of-day if 24/7 access is not required.",
          complianceFrameworks: ["NIST_AI_RMF", MITRE_ATLAS],
          reference: event.EventId ? `https://console.aws.amazon.com/cloudtrail/home?region=${region}#/eventHistory?EventSource=bedrock.amazonaws.com` : undefined,
        });
      }
    }
  }

  // ── 2. Resolve model-invocation logging config ─────────────
  let cloudWatchLogGroup: string | null = null;
  let s3Only = false;
  try {
    const loggingConfig = await bedrock.send(new GetModelInvocationLoggingConfigurationCommand({}));
    const cfg2 = loggingConfig.loggingConfig;
    if (cfg2?.cloudWatchConfig?.logGroupName) {
      cloudWatchLogGroup = cfg2.cloudWatchConfig.logGroupName;
    } else if (cfg2?.s3Config?.bucketName) {
      s3Only = true;
    }
    // If neither is enabled, Tool 1's bedrock-logging-disabled finding covers it.
  } catch (err) {
    findings.push({
      findingId: "prompt-scan-logging-config-error",
      ruleId: "prompt-scan-logging-unavailable",
      title: "Could not read Bedrock logging configuration",
      severity: "low",
      status: "ERROR",
      resource: "bedrock:model-invocation-logging",
      region,
      details: `Failed to call GetModelInvocationLoggingConfiguration: ${(err as Error).message}`,
      remediation: "Verify IAM permissions: bedrock:GetModelInvocationLoggingConfiguration",
      complianceFrameworks: ["NIST_AI_RMF", MITRE_ATLAS],
    });
  }

  // ── 3. S3-only logging: content scan not supported in MVP ─
  if (s3Only) {
    findings.push({
      findingId: "prompt-scan-s3-only",
      ruleId: "prompt-scan-logging-unavailable",
      title: "Prompt content scan skipped: S3-only logging destination",
      severity: "medium",
      status: "NOT_APPLICABLE",
      resource: "bedrock:model-invocation-logging",
      region,
      details: "Model-invocation logging is enabled with an S3 destination only. The MVP content scanner reads CloudWatch Logs; S3 Select / Athena integration is planned post-weekend. Off-hours and volume anomaly detection still ran from CloudTrail metadata.",
      remediation: "To enable prompt content scanning, add a CloudWatch Logs destination to the Bedrock model-invocation logging configuration.",
      complianceFrameworks: ["NIST_AI_RMF"],
    });
  }

  // ── 4. CloudWatch Logs: regex + token-count on real prompt bodies ──
  if (cloudWatchLogGroup) {
    const { events: logEvents, error } = await readInvocationLogs(logs, cloudWatchLogGroup, hoursBack, maxEvents);
    if (error) {
      findings.push({
        findingId: "prompt-scan-log-read-error",
        ruleId: "prompt-scan-logging-unavailable",
        title: "Could not read Bedrock invocation logs",
        severity: "low",
        status: "ERROR",
        resource: cloudWatchLogGroup,
        region,
        details: error,
        remediation: "Verify IAM permissions: logs:FilterLogEvents on the Bedrock invocation log group. Verify the log group exists and has retention covering the requested window.",
        complianceFrameworks: ["NIST_AI_RMF", MITRE_ATLAS],
      });
    }

    for (const ev of logEvents) {
      // Guardrail-less invocation detection (CloudWatch Logs source).
      if (!ev.guardrailApplied) {
        recordGuardless(ev.principal, `log:${ev.logEventId}`);
      }
      // 4a. Regex signature match against the full request body string.
      for (const sig of INJECTION_SIGNATURES) {
        let matched = false;
        for (const pattern of sig.patterns) {
          if (pattern.test(ev.bodyText)) { matched = true; break; }
        }
        if (matched) {
          const signal: PromptInjectionSignal = {
            eventId: ev.logEventId,
            timestamp: ev.timestamp.toISOString(),
            principal: ev.principal,
            modelId: ev.modelId,
            pattern: sig.name,
            severity: "critical",
            matchedText: ev.bodyText.slice(0, 200),
            rawEvent: ev.logEventId,
          };
          signals.push(signal);
          findings.push({
            findingId: `prompt-injection-${sig.name}-${ev.logEventId}`,
            ruleId: `prompt-injection-${sig.name}`,
            title: `Prompt injection signature detected: ${sig.name}`,
            severity: "critical",
            status: "FAIL",
            resource: ev.principal,
            region,
            details: `Invocation log event ${ev.logEventId} matched "${sig.name}" pattern. Model: ${ev.modelId}. Principal: ${ev.principal}. Time: ${ev.timestamp.toISOString()}. Request body (truncated, 200 chars): "${ev.bodyText.slice(0, 200)}${ev.bodyText.length > 200 ? "..." : ""}"`,
            remediation: "1. Investigate the invocation log event. 2. Review the calling application — it may be compromised or lacking input sanitization. 3. Enable Bedrock Guardrails with the prompt-attack content filter at HIGH strength. 4. Add a pre-processing step to sanitize user inputs before they reach Bedrock.",
            complianceFrameworks: SIGNATURE_COMPLIANCE[sig.name] ?? [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, MITRE_ATLAS],
            reference: `https://console.aws.amazon.com/cloudwatch/home?region=${region}#logsV2:log-groups/log-group/${encodeURIComponent(cloudWatchLogGroup)}`,
          });
          // NOTE: no break — an event carrying multiple signature categories
          // (e.g. "ignore previous instructions AND reveal your system prompt")
          // produces one finding per category (TEST_PLAN T2.2).
        }
      }

      // 4b. Real token-count check from log metadata (not the caller's maxTokens cap).
      if (typeof ev.totalTokenCount === "number" && ev.totalTokenCount > tokenThreshold) {
        findings.push({
          findingId: `excessive-tokens-${ev.logEventId}`,
          ruleId: "excessive-token-usage",
          title: `High token count Bedrock invocation: ${ev.totalTokenCount} tokens`,
          severity: "low",
          status: "FAIL",
          resource: ev.principal,
          region,
          details: `Invocation log event ${ev.logEventId} consumed ${ev.totalTokenCount} tokens (threshold: ${tokenThreshold}). Model: ${ev.modelId}. Principal: ${ev.principal}. High output token counts can indicate data exfiltration via repeated large responses.`,
          remediation: "1. Verify this token usage is expected for the use case. 2. Consider model-specific maxTokens limits via Bedrock Guardrails or application-level controls. 3. Watch for data exfiltration patterns (high output tokens = potentially exfiltrating retrieved context).",
          complianceFrameworks: [OWASP_LLM_TOP10.LLM10_UNBOUNDED_CONSUMPTION, "NIST_AI_RMF"],
        });
      }
    }
  }

  // ── 4c. Guardrail-less invocation summaries (one per principal) ────
  for (const [principal, count] of guardlessCounts) {
    findings.push({
      findingId: `guardrail-less-invocation-${principal.replace(/[^a-zA-Z0-9]/g, "-")}`,
      ruleId: "guardrail-less-invocation",
      title: `Bedrock invocations without a guardrail: ${principal}`,
      severity: "medium",
      status: "FAIL",
      resource: principal,
      region,
      details: `Principal ${principal} made ${count} Bedrock invocation(s) without a guardrail attached (no guardrailId in the request). These invocations had no preventive content-filter, PII, or topic controls applied at the Bedrock layer. This is the runtime counterpart to Tool 1's guardrail-quality findings.`,
      remediation: "Associate a Bedrock Guardrail (HIGH-strength prompt-attack filter minimum) with the application making these calls. Pass guardrailId + guardrailVersion in the InvokeModel request, or attach the guardrail to the Bedrock application/agent.",
      complianceFrameworks: [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, OWASP_LLM_TOP10.LLM06_EXCESSIVE_AGENCY, OWASP_AGENTIC.ASI03_IDENTITY_PRIVILEGE, MITRE_ATLAS],
      reference: "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
    });
  }

  // ── 5. Result assembly ─────────────────────────────────────
  // Keep ALL prompt-injection and excessive-token findings — each is a discrete
  // incident. Collapse only the synthetic off-hours summary to the latest per principal.
  const collapsed = new Map<string, BedrockSecurityFinding>();
  const retained: BedrockSecurityFinding[] = [];
  for (const f of findings) {
    if (f.ruleId === "off-hours-bedrock-usage") {
      collapsed.set(f.resource, f); // last one wins per principal
    } else {
      retained.push(f);
    }
  }
  const result = [...retained, ...collapsed.values()];

  if (result.length === 0) {
    return [{
      findingId: "prompt-injection-clean",
      ruleId: "no-injection-signals",
      title: "No prompt injection signals detected",
      severity: "low",
      status: "PASS",
      resource: "bedrock:invocation-logs",
      region,
      details: `Scanned ${trailEventCount} Bedrock InvokeModel CloudTrail events and ${cloudWatchLogGroup ? "model-invocation logs" : "no CloudWatch log source (logging disabled)"} over the last ${hoursBack} hours. No prompt-injection signatures, anomalous off-hours usage, or excessive token counts detected.`,
      remediation: "Continue monitoring. Consider enabling Bedrock Guardrails for proactive defense.",
      complianceFrameworks: [OWASP_LLM_TOP10.LLM01_PROMPT_INJECTION, "NIST_AI_RMF"],
    }];
  }

  return result;
}
