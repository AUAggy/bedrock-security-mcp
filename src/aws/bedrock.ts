// src/aws/bedrock.ts

import {
  BedrockClient,
  ListGuardrailsCommand,
  GetGuardrailCommand,
} from "@aws-sdk/client-bedrock";

export interface GuardrailSummary {
  guardrailId: string;
  guardrailArn: string;
  name: string;
  version: string;
  description?: string;
}

/** List all guardrails in the account/region. */
export async function listGuardrails(bedrock: BedrockClient): Promise<GuardrailSummary[]> {
  const out: GuardrailSummary[] = [];
  let nextToken: string | undefined;
  do {
    const resp = await bedrock.send(new ListGuardrailsCommand({ nextToken }));
    for (const g of resp.guardrails ?? []) {
      out.push({
        guardrailId: g.id ?? "",
        guardrailArn: g.arn ?? "",
        name: g.name ?? "",
        version: g.version ?? "",
        description: g.description,
      });
    }
    nextToken = resp.nextToken;
  } while (nextToken);
  return out;
}

/** Normalized guardrail config for the rule engine. */
export interface GuardrailConfig {
  guardrailId: string;
  guardrailArn: string;
  name: string;
  version: string;
  contentFilters: Array<{ type: string; inputStrength?: string; outputStrength?: string }>;
  hasPromptAttackFilter: boolean;
  minContentStrength: string;   // weakest strength across configured content filters
  piiEntityCount: number;
  deniedTopicCount: number;
  hasGrounding: boolean;
}

const STRENGTH_RANK: Record<string, number> = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
const RANK_STRENGTH = ["NONE", "LOW", "MEDIUM", "HIGH"];

/** Fetch + normalize a guardrail's config. Returns { config, error } — never throws. */
export async function getGuardrailConfig(
  bedrock: BedrockClient,
  guardrail: GuardrailSummary
): Promise<{ config: GuardrailConfig | null; error?: string }> {
  try {
    const resp = await bedrock.send(new GetGuardrailCommand({
      guardrailIdentifier: guardrail.guardrailArn || guardrail.guardrailId,
      guardrailVersion: guardrail.version || undefined,
    }));
    const contentFilters = (resp.contentPolicy?.filters ?? []).map(f => ({
      type: String(f.type ?? ""),
      inputStrength: f.inputStrength as string | undefined,
      outputStrength: f.outputStrength as string | undefined,
    }));
    const pii = resp.sensitiveInformationPolicy?.piiEntities ?? [];
    const topics = resp.topicPolicy?.topics ?? [];
    const grounding = resp.contextualGroundingPolicy?.filters ?? [];

    const rank = (s?: string): number => STRENGTH_RANK[s?.toUpperCase() ?? ""] ?? 0;
    const minContentStrength = contentFilters.length === 0
      ? "NONE"
      : contentFilters.reduce((min, f) => {
          const m = Math.min(rank(f.inputStrength), rank(f.outputStrength));
          return m < rank(min) ? (RANK_STRENGTH[m] ?? "NONE") : min;
        }, "HIGH");

    return {
      config: {
        guardrailId: guardrail.guardrailId,
        guardrailArn: guardrail.guardrailArn,
        name: resp.name ?? guardrail.name,
        version: resp.version ?? guardrail.version,
        contentFilters,
        hasPromptAttackFilter: contentFilters.some(f => f.type === "PROMPT_ATTACK"),
        minContentStrength,
        piiEntityCount: pii.length,
        deniedTopicCount: topics.length,
        hasGrounding: grounding.length > 0,
      },
    };
  } catch (err) {
    return { config: null, error: `GetGuardrail failed for ${guardrail.name} (${guardrail.guardrailId}): ${(err as Error).message}` };
  }
}
