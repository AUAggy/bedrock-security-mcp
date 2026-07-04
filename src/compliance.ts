// src/compliance.ts

/** OWASP LLM Top 10 (2025) */
export const OWASP_LLM_TOP10 = {
  LLM01_PROMPT_INJECTION:     "OWASP_LLM_TOP10:LLM01" as const,
  LLM02_SENSITIVE_INFO:       "OWASP_LLM_TOP10:LLM02" as const,
  LLM05_IMPROPER_OUTPUT:      "OWASP_LLM_TOP10:LLM05" as const,
  LLM06_EXCESSIVE_AGENCY:     "OWASP_LLM_TOP10:LLM06" as const,
  LLM07_SYSTEM_PROMPT_LEAK:   "OWASP_LLM_TOP10:LLM07" as const,
  LLM08_VECTOR_WEAKNESSES:    "OWASP_LLM_TOP10:LLM08" as const,
  LLM10_UNBOUNDED_CONSUMPTION:"OWASP_LLM_TOP10:LLM10" as const,
} as const;

/** OWASP Top 10 for Agentic Applications (Dec 2025) */
export const OWASP_AGENTIC = {
  ASI01_GOAL_HIJACK:          "OWASP_AGENTIC:ASI01" as const,
  ASI02_TOOL_MISUSE:          "OWASP_AGENTIC:ASI02" as const,
  ASI03_IDENTITY_PRIVILEGE:   "OWASP_AGENTIC:ASI03" as const,
  ASI04_SUPPLY_CHAIN:         "OWASP_AGENTIC:ASI04" as const,
  ASI05_UNEXPECTED_CODE_EXEC: "OWASP_AGENTIC:ASI05" as const,
  ASI07_INSECURE_INTER_AGENT: "OWASP_AGENTIC:ASI07" as const,
  ASI08_CASCADING_FAILURES:   "OWASP_AGENTIC:ASI08" as const,
} as const;

export const NIST_AI_RMF = "NIST_AI_RMF" as const;
export const MITRE_ATLAS = "MITRE_ATLAS" as const;

/** AWS Well-Architected Framework — Machine Learning Lens */
export const AWS_WA_ML_LENS = {
  SEC_3:  "AWS_WA_ML:SEC-3" as const,   // Identity & access management for ML resources
  SEC_6:  "AWS_WA_ML:SEC-6" as const,   // Data protection for ML workloads
  SEC_10: "AWS_WA_ML:SEC-10" as const,  // Incident response readiness
  OPS_8:  "AWS_WA_ML:OPS-8" as const,   // Monitoring & observability for ML
} as const;
