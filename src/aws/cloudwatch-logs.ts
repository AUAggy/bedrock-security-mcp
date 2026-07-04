// src/aws/cloudwatch-logs.ts

import {
  CloudWatchLogsClient,
  FilterLogEventsCommand,
} from "@aws-sdk/client-cloudwatch-logs";

/** A parsed Bedrock model-invocation log event. */
export interface InvocationLogEvent {
  logEventId: string;
  timestamp: Date;
  principal: string;        // identity.arn from the log, falling back to "unknown"
  modelId: string;
  totalTokenCount?: number; // metadata.totalTokenCount — the real consumed count
  /** True if the invocation applied a guardrail (request.guardrail present). */
  guardrailApplied: boolean;
  /** Stringified request body. Regex run against this catches injection phrases
   * wherever they appear (messages[].content, system prompt, tool descriptions). */
  bodyText: string;
}

/**
 * Read Bedrock model-invocation log events from a CloudWatch Logs log group.
 * Paginates up to maxEvents. Returns parsed events; never throws — errors bubble
 * to the caller as an `error` field so Tool 2 can surface them as ERROR findings.
 */
export async function readInvocationLogs(
  logs: CloudWatchLogsClient,
  logGroupName: string,
  hoursBack: number,
  maxEvents: number
): Promise<{ events: InvocationLogEvent[]; error?: string }> {
  const startTime = new Date(Date.now() - hoursBack * 60 * 60 * 1000);
  const endTime = new Date();
  const out: InvocationLogEvent[] = [];
  let nextToken: string | undefined;

  try {
    do {
      const resp = await logs.send(new FilterLogEventsCommand({
        logGroupName,
        startTime: startTime.getTime(),
        endTime: endTime.getTime(),
        limit: Math.min(Math.max(maxEvents - out.length, 1), 10000),
        nextToken,
      }));
      for (const ev of resp.events ?? []) {
        const parsed = parseInvocationMessage(ev.message ?? "", ev.eventId ?? "", ev.timestamp ?? 0);
        if (parsed) out.push(parsed);
        if (out.length >= maxEvents) break;
      }
      nextToken = resp.nextToken;
    } while (nextToken && out.length < maxEvents);
    return { events: out };
  } catch (err) {
    return { events: out, error: `FilterLogEvents failed on '${logGroupName}': ${(err as Error).message}` };
  }
}

/** Parse a single Bedrock invocation-log message. Returns null for non-model-invocation entries. */
function parseInvocationMessage(
  raw: string,
  logEventId: string,
  ts: number
): InvocationLogEvent | null {
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch {
    return null;
  }
  // Actual Bedrock invocation-log schema (verified against a real account):
  // { timestamp, accountId, region, requestId, operation, modelId,
  //   input: { inputBodyJson, inputTokenCount },
  //   output: { outputBodyJson, outputTokenCount } }
  // There is no "schema-type" field and no "request"/"identity"/"metadata" wrapper.
  // The prompt body lives in input.inputBodyJson (already a parsed object).
  // Identity is NOT in the log — it comes from CloudTrail; use "unknown" here.
  if ((obj as any)?.operation !== "InvokeModel") return null;

  const input = (obj as any).input ?? {};
  const output = (obj as any).output ?? {};
  // inputBodyJson is already a parsed object; stringify so regex matches across
  // the whole request payload (messages[].content, system, etc.).
  const bodyText = typeof input.inputBodyJson === "string"
    ? input.inputBodyJson
    : JSON.stringify(input.inputBodyJson ?? "");

  return {
    logEventId,
    timestamp: ts ? new Date(ts) : new Date(),
    principal: "unknown",  // not in the log; CloudTrail provides the principal
    modelId: (obj as any).modelId ?? "unknown",
    totalTokenCount: (input.inputTokenCount ?? 0) + (output.outputTokenCount ?? 0) || undefined,
    guardrailApplied: !!(input.guardrail || input.guardrailId),
    bodyText,
  };
}
