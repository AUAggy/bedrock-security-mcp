// src/types.ts

/** Severity levels aligned to GuardDuty → SPM mapping */
export type Severity = "critical" | "high" | "medium" | "low";

/** Finding status */
export type FindingStatus = "FAIL" | "PASS" | "ERROR" | "NOT_APPLICABLE";

/** The universal output type — every tool returns this */
export interface BedrockSecurityFinding {
  findingId: string;                   // e.g. "bedrock-iam-wildcard-action-AdminRole"
  ruleId: string;                      // e.g. "wildcard-bedrock-action"
  title: string;                       // Human-readable, e.g. "AdminRole has wildcard bedrock:*"
  severity: Severity;
  status: FindingStatus;
  resource: string;                    // ARN of the role, guardrail, model, etc.
  region: string;
  details: string;                     // What's wrong, with specifics
  remediation: string;                 // Concrete fix steps or AWS CLI commands
  complianceFrameworks: string[];      // OWASP LLM Top 10, OWASP Agentic, NIST AI RMF, MITRE ATLAS
  reference?: string;                  // Link to AWS docs or relevant standard
}

/** The shape of a single policy statement that's been analyzed */
export interface AnalyzedStatement {
  sid: string;
  effect: "Allow" | "Deny";
  actions: string[];       // e.g. ["bedrock:InvokeModel", "bedrock:*"]
  resources: string[];     // e.g. ["*", "arn:aws:bedrock:..."]
  hasWildcardAction: boolean;
  hasWildcardResource: boolean;
  hasCondition: boolean;
  conditionKeys: string[]; // e.g. ["aws:SourceIp", "aws:RequestedRegion"]
  principals: string[];    // from trust policy — ["*"] = critical
  /** True if the statement uses NotAction (inverted action match — manual review). */
  usesNotAction: boolean;
  /** True if the statement uses NotResource (inverted resource match — manual review). */
  usesNotResource: boolean;
  /** Set when the policy document could not be parsed; rule engine surfaces this as ERROR. */
  parseError?: string;
}

/** CloudTrail event that matched an injection or anomaly pattern */
export interface PromptInjectionSignal {
  eventId: string;
  timestamp: string;
  principal: string;       // IAM principal that called InvokeModel
  modelId: string;         // e.g. "anthropic.claude-sonnet-4-20250514-v1:0"
  pattern: string;         // Which pattern matched: "ignore-previous-instructions" | "off-hours-spike" | "excessive-tokens"
  severity: Severity;
  matchedText?: string;    // The text that triggered the match (truncated to 200 chars)
  rawEvent: string;        // CloudTrail event ID for reference
}
