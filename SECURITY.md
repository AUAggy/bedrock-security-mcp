# Security Policy

## What this tool does (and doesn't do)

bedrock-security-mcp is a read-only MCP server. It audits AWS Bedrock posture (model-invocation logging, invocation-log KMS encryption, Guardrail quality, and IAM over-permissioning), scans CloudTrail and invocation logs for prompt-injection signals, and generates posture reports. It never mutates AWS resources. It never stores credentials. It never phones home.

The following properties are design constraints, not marketing claims. A security auditor should verify each one.

| Property | How it's enforced | How to verify |
|---|---|---|
| Read-only AWS operations | Only `List*`, `Get*`, `Lookup*`, and `Describe*` API calls. No `Put*`, `Create*`, `Delete*`, `Update*`, or `Modify*` calls appear anywhere in the codebase | `grep -r "\.send(new" src/ | grep -iv "List\|Get\|Lookup\|Describe"` |
| No credential storage | The AWS SDK reads credentials from the standard provider chain (env vars, `~/.aws/`, SSO). The tool never parses, stores, or transmits credential material | No calls to `fs.writeFile` with credential data. Environment-variable capture is limited to `AWS_REGION`, `AWS_PROFILE`, `BEDROCK_SECURITY_OUTPUT_DIR`, and `BEDROCK_SECURITY_ACCOUNT_ID` — none of which are credentials |
| No outbound network calls except AWS APIs | The tool talks only to AWS service endpoints via the SDK. No telemetry, no analytics, no update checks | `grep -r "fetch\|http.request\|https.request\|axios\|got\|node-fetch" src/` |
| Credentials never reach the LLM | The MCP protocol returns structured `BedrockSecurityFinding[]` objects. These contain resource ARNs, finding titles, and remediation text — never access keys, session tokens, or full prompt bodies | Every response passes through JSON serialization. Prompt-body text matched from CloudWatch Logs is truncated to 200 characters before inclusion in findings |
| Stdio transport only | The server communicates over stdin/stdout. No HTTP, no SSE, no WebSocket, no TCP listener | Single `StdioServerTransport` instantiation in `src/index.ts` |

## The tool's own IAM permissions

The tool itself needs AWS credentials to run. Deploy this policy to the IAM principal that executes the MCP server. This is the minimum set — every permission maps to a specific API call in the codebase.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadIAMForBedrockAudit",
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadCloudTrailForBedrockEvents",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadBedrockConfiguration",
      "Effect": "Allow",
      "Action": [
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:ListGuardrails",
        "bedrock:GetGuardrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadInvocationLogsForPromptScan",
      "Effect": "Allow",
      "Action": [
        "logs:FilterLogEvents",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

**Why each statement exists:**

| Statement | API calls this enables | Tool that uses it |
|---|---|---|
| `ReadIAMForBedrockAudit` | `ListRoles` (returns trust policies + inline policy names), `GetRolePolicy`, `ListAttachedRolePolicies`, `ListRolePolicies`, `GetPolicy`, `GetPolicyVersion` | `audit_bedrock_posture` |
| `ReadCloudTrailForBedrockEvents` | `LookupEvents` (filtered to `bedrock.amazonaws.com`), `DescribeTrails` (management-enabled guard) | `find_prompt_injection_signals` (off-hours / volume / guardrail-less detection) |
| `ReadBedrockConfiguration` | `GetModelInvocationLoggingConfiguration`, `ListGuardrails`, `GetGuardrail` | `audit_bedrock_posture` (logging + KMS check + guardrail-quality rules), `find_prompt_injection_signals` (resolve CloudWatch log group) |
| `ReadInvocationLogsForPromptScan` | `FilterLogEvents` on the Bedrock invocation log group, `DescribeLogGroups` (KMS check) | `find_prompt_injection_signals` (prompt-body regex + token-count check), `audit_bedrock_posture` (invocation-log KMS) |

No `iam:GetRole` (ListRoles returns the trust policy). No `iam:ListAccountAliases` (account ID is parsed from a role ARN). No `iam:PassRole`. No `bedrock:InvokeModel`. No `cloudtrail:CreateTrail`. If you restrict this policy further (e.g., add `aws:RequestedRegion` condition), the tool degrades gracefully with a clear error message — never a stack trace.

## Supply chain

### Dependencies

The tool has five runtime dependencies:

| Dependency | Version | Purpose | Risk |
|---|---|---|---|
| `@modelcontextprotocol/sdk` | ^1.12 | MCP protocol implementation | Maintained by Anthropic. The SDK does not make outbound network calls beyond the MCP transport |
| `@aws-sdk/client-iam` | ^3.700 | IAM API calls | AWS-maintained. Part of the official JavaScript SDK |
| `@aws-sdk/client-cloudtrail` | ^3.700 | CloudTrail API calls | AWS-maintained |
| `@aws-sdk/client-bedrock` | ^3.700 | Bedrock logging-config API calls | AWS-maintained |
| `@aws-sdk/client-cloudwatch-logs` | ^3.700 | CloudWatch Logs `FilterLogEvents` for prompt-body scan | AWS-maintained |

No other runtime dependencies. No `zod`, `yup`, `lodash`, or utility libraries — validation is done through TypeScript types and manual guards inside tool handlers.

### Lockfile

`package-lock.json` is committed to the repository and pins the exact resolved version of every package in the dependency tree (`package.json` declares semver ranges; the lockfile is what installs). `npm ci` is used in CI to ensure reproducible builds.

### Provenance

Releases are published to npm with SLSA provenance via GitHub Actions. Running `npm view bedrock-security-mcp` shows the source repository and build commit:

```
provenance:
  predicateType: https://slsa.dev/provenance/v1
  sourceRepository: github.com/AUAggy/bedrock-security-mcp
  builder: GitHub Actions
```

### Dependency audit

Run `npm audit` before each release. Critical and high-severity advisories block publishing. The CI pipeline runs `npm audit --audit-level=high` as a gate.

## Threat model

This section describes credible threats to a user running this MCP server, and what controls exist.

### T1: Compromised npm package

**Threat:** An attacker publishes a malicious version of `bedrock-security-mcp` to npm, or compromises a dependency.

**Impact:** The malicious code runs with the user's AWS credentials. It can access any resource those credentials grant.

**Controls:**
- Minimal dependency footprint (4 AWS SDK packages + the MCP SDK)
- npm provenance links each release to a specific GitHub commit
- README includes `npx bedrock-security-mcp` with `-y` flag — users can pin versions with `npx bedrock-security-mcp@0.1.0`
- `package-lock.json` is committed — dependency tree is auditable

**Residual risk:** Medium. Publishing uses npm Trusted Publishing (OIDC) from GitHub Actions, so no long-lived publish token exists to steal; the remaining path is a compromise of the repository or its release workflow. Users should pin to a specific version.

### T2: Malicious LLM prompt manipulates findings

**Threat:** A user's LLM (Claude) is prompted to lie about the findings. The attacker injects a prompt that tells Claude to ignore critical findings or fabricate false reassurances.

**Impact:** The user believes their Bedrock posture is clean when it's not. They skip remediation.

**Controls:**
- Findings are returned as structured JSON, not natural language summaries. Claude cannot silently drop a finding without the user noticing a change in count
- The HTML report is generated server-side from raw finding data — the LLM sees the same structured output the user does
- The user can run `generate_ai_posture_report` to get a file they can inspect independently of the LLM's interpretation

**Residual risk:** Medium. The LLM interprets findings for the user. This is inherent to MCP — the LLM is the UI. The control is that the underlying data is always available in structured form.

### T3: Over-privileged AWS credentials

**Threat:** The user runs the MCP server with AWS credentials that have more permissions than the documented minimum.

**Impact:** If the MCP server is compromised (T1), the blast radius is larger than necessary.

**Controls:**
- The SECURITY.md documents the minimum IAM policy explicitly
- The tool fails clearly (not silently) when it lacks required permissions, encouraging users to scope credentials correctly rather than grant `*`
- README includes a warning: "This tool needs only the permissions listed in SECURITY.md. Do not run it with AdministratorAccess."

**Residual risk:** Medium. Users often run tools with broad permissions for convenience. Documentation can only recommend, not enforce.

### T4: Information disclosure through findings

**Threat:** Findings returned to the LLM contain sensitive information — role names that reveal internal naming conventions, ARNs that expose account structure, or CloudTrail event text that contains actual prompts with PII.

**Impact:** The LLM provider (Anthropic) could see these details if the user is using a cloud-hosted LLM.

**Controls:**
- Raw prompt-body text matched from CloudWatch Logs is truncated to 200 characters in findings. The full prompt is never returned to the LLM
- The tool never returns full policy documents — only the specific statement that triggered a finding
- The HTML report is written locally, not transmitted

**Residual risk:** Low. Findings necessarily include resource identifiers (role names, ARNs) — that's the point. Users who audit production accounts with a cloud-hosted LLM should be aware that resource identifiers are visible to the model provider.

### T5: LLM client declines or fails to invoke the tool

**Threat:** The user's MCP-client LLM declines to call `audit_bedrock_posture` or to relay findings — conservative safety tuning that misclassifies defensive auditing as offensive activity, a strict refusal policy in a custom fine-tune, or plain tool-routing failure. The audit becomes gated on a model decision.

**Impact:** The user cannot run the audit via chat even though the tool itself works.

**Controls:**
- The `audit` CLI subcommand (`npx bedrock-security-mcp audit`) runs the full audit with no LLM in the loop — it imports `generateAiPostureReport` directly and writes the report to disk. No model decision can gate it.
- The CLI is also the CI entrypoint, so automated scans never depend on an LLM.
- Tool descriptions state their defensive purpose plainly ("audit posture", "detect signals"), which is both accurate and helps conservative models route the request correctly. When a client model still declines, the CLI is the supported path.

**Residual risk:** Low. The LLM is a *preferred* interface, not a *required* one. The canonical artifact (markdown + HTML on disk) is producible without any LLM.

### T6: Non-determinism from LLM interpretation

**Threat:** Different LLMs (Claude Haiku vs Opus, Gemini, DeepSeek) produce different in-chat summaries of the same findings, or choose different scan scopes (e.g., `hoursBack: 24` vs `72`), making results appear non-reproducible.

**Impact:** Users compare chat output across models/teams and believe the tool is flaky.

**Controls:**
- The report artifact (markdown, HTML, JSON) is generated server-side by pure functions of AWS state and is fully deterministic and model-independent. Same account state + same params → byte-identical artifact, every time.
- The CLI (`audit --json --region R --hours H --out-dir D`) is byte-reproducible across machines with zero LLM in the loop.
- For reproducible interactive scans, users pin params explicitly ("scan the last 24 hours") and set `BEDROCK_SECURITY_OUTPUT_DIR` so the file is canonical and the chat is a preview.

**Residual risk:** Low. Only the LLM's conversational wrapping varies; the underlying data and the written report do not.

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/AUAggy/bedrock-security-mcp/security/advisories/new). Do not open a public issue for security vulnerabilities. You will receive a response within 48 hours.

This project follows a coordinated disclosure process. Critical vulnerabilities will be patched and a GitHub Security Advisory published within 7 days.

## Design principles

These principles guided every architectural decision. They are stated here so an auditor can evaluate whether the implementation matches the intent.

1. **Read-only by construction.** The codebase contains no function that calls a mutating AWS API. This is verifiable by grep, not by trusting documentation.

2. **Credentials stay in the process tree.** The AWS SDK credential chain reads from the local machine. The MCP server never parses, stores, or transmits credentials. The LLM receives only structured findings.

3. **No security theatre.** Every check the tool performs maps to a specific, articulable risk. If a check cannot be justified with a concrete threat scenario and a specific framework reference, it is not included. Generic "security hardening" checks that produce noise without signal are explicitly out of scope.

4. **Least-privilege for the tool itself.** The documented IAM policy grants exactly the permissions the tool needs — no `*` on actions, no `*` on resources unless the API requires it (IAM `ListRoles` requires `Resource: "*"`). If a permission can be scoped, it is.

5. **Fail closed with clear errors.** When the tool lacks permissions, it returns a finding with `status: ERROR` and a human-readable message — never a stack trace, never a silent skip. The user knows exactly what failed and what to fix.

6. **Deterministic artifact, model-independent.** The report (markdown, HTML, JSON) is generated server-side by pure functions of AWS state. Same account + same params → byte-identical artifact regardless of which LLM calls the tool. The LLM is a *preferred* interface, not a *required* one — the `audit` CLI runs the same code with no LLM in the loop, for CI and for any client model that declines or fails to call the tool.

7. **Two entrypoints, one code path.** The MCP stdio server and the `audit` CLI both call `generateAiPostureReport`. No logic is duplicated between interactive and automated use. The CLI is the CI gate and the LLM-independent fallback; the MCP server is the conversational interface.
