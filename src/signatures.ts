// src/signatures.ts

/** Known prompt injection patterns (case-insensitive) */
export const INJECTION_SIGNATURES: Array<{ name: string; patterns: RegExp[]; severity: "critical" }> = [
  {
    name: "ignore-previous-instructions",
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|directives?|commands?|prompts?)/i,
      /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|directives?)/i,
      /forget\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|prompts?)/i,
      /override\s+(all\s+)?(previous|prior)\s+(instructions?|directives?)/i,
    ],
    severity: "critical",
  },
  {
    name: "system-prompt-leak",
    patterns: [
      /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?|system\s+message)/i,
      /tell\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
      /what\s+(is|are)\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
      /print\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
      /show\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
      /output\s+(your|the)\s+(original|initial|system)\s+(prompt|instructions?)/i,
    ],
    severity: "critical",
  },
  {
    name: "roleplay-jailbreak",
    patterns: [
      /you\s+are\s+now\s+(DAN|STAN|DUDE|jailbreak)/i,
      /pretend\s+(you\s+are|to\s+be)\s+a\s+(different|new|unrestricted|uncensored)\s+(AI|model|assistant)/i,
      /act\s+as\s+if\s+you\s+(have|are)\s+no\s+(restrictions?|limitations?|rules?|guidelines?)/i,
      /from\s+now\s+on\s+you\s+(are|will\s+be)\s+(DAN|a\s+different\s+AI)/i,
    ],
    severity: "critical",
  },
  {
    name: "token-smuggling",
    patterns: [
      /respond\s+with\s+(your|the)\s+(raw\s+)?token\s+(log|output|stream)/i,
      /output\s+(your|the)\s+(internal\s+)?(reasoning|chain.of.thought|thinking)/i,
      /\[\s*REASONING\s*\]|\[THINK\]|\[INTERNAL\]/i,
    ],
    severity: "critical",
  },
];

/**
 * Default token-count threshold for the excessive-tokens check. Configurable
 * via the tool's `tokenThreshold` parameter. The value is a heuristic, not a
 * measured percentile — tune it to your workload's normal max.
 */
export const DEFAULT_TOKEN_THRESHOLD = 100000;

/** Off-hours definition: UTC hours outside typical business hours */
export function isOffHours(date: Date): boolean {
  const hours = date.getUTCHours();
  const day = date.getUTCDay();
  // Weekends or 10 PM - 6 AM UTC
  return day === 0 || day === 6 || hours < 6 || hours >= 22;
}
