# bedrock-security-mcp

An MCP server with a CI-grade CLI. It audits the security posture of AWS Bedrock workloads: IAM roles with Bedrock permissions, model-invocation logging and its KMS encryption, guardrail quality, and prompt-injection signals in your invocation logs. Findings map to OWASP LLM Top 10 (2025), OWASP Agentic Applications Top 10, NIST AI RMF, and MITRE ATLAS.

Ask Claude to audit your account, or run the same audit from a pipeline with no LLM involved. Both entrypoints call the same code and produce the same findings.

## How it runs

The server is a stdio process on your machine. There is no hosted component.

```
You ask Claude: "audit my Bedrock security posture"
  -> Claude calls the MCP tool
  -> the server queries AWS read-only APIs with your local credentials
  -> structured findings return to Claude for interpretation
```

Credentials come from the standard AWS SDK chain (`AWS_PROFILE`, environment, SSO, instance role). The tool never reads or forwards key material, and the LLM receives structured findings, never raw credentials or full CloudTrail event bodies.

## Quick start

### As an MCP server (Claude Desktop or Claude Code)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bedrock-security": {
      "command": "npx",
      "args": ["-y", "bedrock-security-mcp"],
      "env": {
        "AWS_PROFILE": "default"
      }
    }
  }
}
```

Then ask: "audit my Bedrock posture", "scan for prompt injection signals in the last 6 hours", or "generate a posture report".

### As a CLI (humans and CI)

```bash
npx bedrock-security-mcp audit --region us-east-1 --out-dir ./reports
```

This prints a markdown report to stdout, writes a self-contained HTML report to `./reports/`, and exits non-zero when blocking findings exist. No LLM is involved; output is deterministic for a given account state.

| Flag | Effect |
|---|---|
| `--region <region>` | AWS region (default: `AWS_REGION` or `us-east-1`) |
| `--role <roleName>` | Audit a single IAM role |
| `--hours <n>` | Hours of CloudTrail and invocation-log history (default 24, clamped to 1..2160 = 90 days, CloudTrail's retention cap) |
| `--out-dir <path>` | Directory for the HTML report (default: current directory; created if missing) |
| `--title <title>` | Report title |
| `--json` | Print raw findings as JSON instead of markdown |

Exit codes: `0` when no critical or high severity FAIL findings exist, `1` when any do, `2` on bad arguments. That makes the CLI a real gate:

```bash
npx bedrock-security-mcp audit --region $AWS_REGION --out-dir reports && echo "posture OK"
```

## Configurations

### Environment variables

The `env` block in the MCP server definition (or your shell for the CLI) controls runtime behavior:

| Variable | Purpose | Default |
|---|---|---|
| `AWS_PROFILE` | AWS credential profile to use | the SDK default chain |
| `AWS_REGION` | Region to audit | `us-east-1` |
| `BEDROCK_SECURITY_OUTPUT_DIR` | Where the HTML report is written (the CLI sets this from `--out-dir`) | none (no HTML written unless set) |
| `BEDROCK_SECURITY_ACCOUNT_ID` | Override the account ID shown in the report header (otherwise resolved from a role ARN) | none |

No log-level variable is exposed. The MCP server logs a single startup line to stderr; the CLI writes the HTML path to stderr and the report to stdout. AWS SDK retries and timeouts use the SDK defaults.

## The three tools

### `audit_bedrock_posture`

Audits configuration and IAM. Checks that model-invocation logging is enabled and its CloudWatch log group uses a customer-managed KMS key. Fetches every guardrail and evaluates filter strength, PII entities, denied topics, and contextual grounding. Enumerates every IAM role, reads managed and inline policies plus trust policies, and flags Bedrock-relevant risk:

| Rule | Severity |
|---|---|
| `wildcard-bedrock-action` | critical |
| `wildcard-principal` | critical |
| `no-condition-keys` | high |
| `cross-account-bedrock-access` | high |
| `bedrock-logging-disabled` | high |
| `guardrail-content-filter-weak` | high |
| `not-action-not-resource` | medium |
| `invocation-logs-without-cmk` | medium |
| `guardrail-no-pii-filter` | medium |
| `guardrail-no-denied-topics` | low |
| `guardrail-grounding-disabled` | low |

### `find_prompt_injection_signals`

Detection over two sources. CloudTrail management events drive off-hours anomaly detection and flag invocations made without a guardrail attached. Bedrock model-invocation logs (CloudWatch destination) carry the actual prompt bodies; the tool scans them against four signature families (`ignore-previous-instructions`, `system-prompt-leak`, `roleplay-jailbreak`, `token-smuggling`) and checks consumed token counts against a threshold.

The tool verifies its own preconditions. A missing CloudTrail trail produces a `cloudtrail-management-disabled` finding rather than a false "no signals detected". Disabled or S3-only invocation logging produces a `prompt-scan-logging-unavailable` finding rather than a silent empty scan.

### `generate_ai_posture_report`

Runs both tools and renders the combined findings as a markdown report (returned to Claude or stdout) plus a self-contained single-file HTML report: severity meter, collapsible finding entries with threat and rationale, remediation roadmap, and a compliance mapping table. Set `BEDROCK_SECURITY_OUTPUT_DIR` (the CLI sets it from `--out-dir`) to write the HTML file.

The posture score is a violation-weighted 0-100 value, not a pass rate. Weights: critical 25, high 10, medium 3, low 1. One critical finding caps the score at 75.

Every rule carries a written threat scenario and a rationale for why the check reduces risk. The full catalog, including compliance mappings, is committed at [`examples/rules-catalog.json`](examples/rules-catalog.json) and regenerated from source via `npm run build:catalog`.

A real report from a sandbox account (identifiers replaced with AWS documentation placeholders) is committed at [`examples/sample-posture-report.html`](examples/sample-posture-report.html).

## Security & Permissions

### Features

The server implements the following security controls:

1. **AWS authentication via the SDK chain.** No credential handling in the tool itself.
2. **Read-only by construction.** Only `List*`, `Get*`, `Lookup*`, `Describe*`, and `Filter*` calls. No `Put*`, `Create*`, `Delete*`, `Update*`, or `InvokeModel` of any kind.
3. **Least privilege.** The documented IAM policy grants exactly the 13 read actions the code calls, each mapped to a specific source function.
4. **Structured findings, not raw data.** The LLM receives `BedrockSecurityFinding[]` objects. Prompt bodies from invocation logs are truncated to 200 characters before inclusion.
5. **Fail closed.** AWS API errors become findings with `status: "ERROR"` and a concrete remediation, never stack traces. Unparseable policy documents surface as ERROR findings instead of passing silently.

### Considerations

When running the server, consider the following:

- **AWS credentials**: the principal needs the read actions listed below. Run it with a dedicated read-only profile, not an admin credential.
- **Network**: the host needs outbound access to AWS service endpoints. No other outbound calls are made.
- **Data exposure**: findings necessarily include resource identifiers (role names, ARNs). If you audit a production account with a cloud-hosted LLM, those identifiers are visible to the model provider.
- **Logging**: enable CloudTrail on the account so the tool's own API calls are auditable.

### Permissions

Deploy [`examples/tool-iam-policy.json`](examples/tool-iam-policy.json) to the principal that runs the audit. It grants exactly the 13 read-only actions the code calls, and nothing else:

- `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`
- `cloudtrail:LookupEvents`, `cloudtrail:DescribeTrails`
- `bedrock:GetModelInvocationLoggingConfiguration`, `bedrock:ListGuardrails`, `bedrock:GetGuardrail`
- `logs:FilterLogEvents`, `logs:DescribeLogGroups`

No `iam:PassRole`, no `bedrock:InvokeModel`, no write actions of any kind. Every action in the policy maps to a specific function in a specific source file.

### Role Scoping Recommendations

In accordance with security best practices:

1. **Create a dedicated IAM principal** for the audit (a role or user used only for this tool), with the policy above attached.
2. **Use a read-only profile.** The documented policy is read-only by construction; do not broaden it with `*` actions or `AdministratorAccess` for convenience.
3. **Constrain by region** where possible. Adding an `aws:RequestedRegion` condition to the policy limits blast radius if the credential leaks.
4. **Enable CloudTrail** on the account so the tool's own `List*`/`Get*` calls are auditable.
5. **Review with IAM Access Analyzer** periodically to confirm no unused permissions have crept in.
6. **Do not reuse a principal** that has Bedrock invocation permissions. The auditor should not be able to invoke models, only inspect the configuration of those who can.

### Sensitive Information Handling

**Do not pass secrets or credentials through the tool.**

- Do not put AWS access keys, session tokens, or secrets in tool parameters or prompts.
- Do not configure `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in the MCP `env` block if you can avoid it. Use a named profile, SSO, or an instance role instead.
- The tool reads only IAM policy documents, CloudTrail event metadata, Bedrock config, guardrail definitions, and invocation-log prompt bodies. It never reads Secrets Manager, Parameter Store, or KMS secret material.

Prompt bodies from invocation logs are truncated to 200 characters in findings. If your prompts may contain PII, be aware that this truncated text is returned to the LLM and written to the local HTML report. For production accounts with sensitive prompts, prefer the CLI mode (output stays on your machine) over an interactive cloud-hosted LLM session.

### File System Access and Operating Mode

This server is intended for **stdio mode only** as a local process using a single user's credentials.

- **Read-only AWS operations.** The server does not write to AWS. It writes one local file: the HTML report, and only when an output directory is configured.
- **Host credentials.** The server uses the host's AWS credentials configuration. It does not read `~/.aws/credentials` itself; the AWS SDK does.
- **No network listener.** No HTTP, no SSE, no WebSocket. Stdin/stdout only.
- **Do not expose over the network.** Network operation introduces authentication and access risks that the design does not address. Run it locally or in CI, not as a shared service.

## Security design

The tool is built to be audited. Each claim below is verifiable against the published source:

- **Read-only by construction.** `grep -r '\.send(new' src/ | grep -iv 'List\|Get\|Lookup\|Describe\|Filter'` returns nothing.
- **No credential handling.** `grep -ri 'ACCESS_KEY\|SECRET_KEY\|sessionToken' src/` returns nothing. The AWS SDK credential chain does all the work.
- **No outbound calls except the AWS SDK.** No fetch, no HTTP clients, no telemetry.
- **Fail closed.** AWS API errors become findings with `status: "ERROR"` and a concrete remediation, never stack traces. Unparseable policy documents surface as ERROR findings instead of passing silently.
- **Five runtime dependencies.** Four AWS SDK clients and the MCP SDK. `package-lock.json` is committed.

The full threat model is in [SECURITY.md](SECURITY.md).

## General Best Practices

- **Pin a version in production.** `npx bedrock-security-mcp@0.1.0` rather than `@latest`, so a malicious or buggy publish cannot change your audit behavior.
- **Run from CI on a schedule.** A daily `audit` job catches configuration drift (a new role, a weakened guardrail, a logging change) before an attacker does.
- **Triage by severity.** Address critical findings within 24 hours, high within a week, medium during the next sprint. The posture score reflects that weighting.
- **Re-run after remediation.** The audit is idempotent and stateless. Fix the issue, re-run, and the finding disappears. No baseline to manage.
- **Use the HTML report for sharing.** It is self-contained and print-safe. The markdown is for chat; the HTML is for the ticket or the board pack.
- **Audit in every region you use Bedrock.** The tool is single-region per run. A multi-region posture requires one run per region.

## General Troubleshooting

- **`AccessDenied` on IAM calls.** Verify the principal has `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`. The error finding names the missing permission.
- **`AccessDenied` on CloudTrail.** Verify `cloudtrail:LookupEvents` and `cloudtrail:DescribeTrails`. Note that `LookupEvents` requires `Resource: "*"`; it cannot be resource-scoped.
- **No prompt-injection findings despite known activity.** Verify model-invocation logging is enabled with a CloudWatch destination (`bedrock:GetModelInvocationLoggingConfiguration`). CloudTrail carries API metadata only, not prompt bodies. If logging is off, the tool emits `bedrock-logging-disabled` and `prompt-scan-logging-unavailable`; it does not silently return empty.
- **`prompt-injection-*` findings show `principal: unknown`.** Bedrock invocation logs do not carry caller identity. Correlate with the CloudTrail-sourced findings (`guardrail-less-invocation`, `off-hours-bedrock-usage`) in the same report, or via CloudTrail event history for the same time window.
- **The CLI exits 1 on a clean account.** Check for high-severity findings. The CI gate fails on critical **or** high, not critical only. A `bedrock-logging-disabled` high finding will block a deploy by design.
- **Large accounts are slow.** IAM enumeration reads every role's policies, 8 requests wide. An account with a few hundred roles audits in roughly a minute. Use `--role <name>` to audit one role during iteration.
- **MCP server does not connect in Claude Desktop.** Run `npx -y bedrock-security-mcp` in a terminal first to confirm it boots. The most common cause is a missing `AWS_PROFILE` in the `env` block or a profile that lacks the read permissions above.

## Limitations

- **Single account, single region per run.** Cross-account and multi-region sweeps are out of scope for v1. Run the CLI once per region or account.
- **S3-only invocation logging is not content-scanned in v1.** The prompt scanner reads the CloudWatch Logs destination. With an S3-only destination the tool reports the gap as a finding and skips the content scan. Add a CloudWatch destination to enable it.
- **Large accounts take time.** IAM enumeration reads every role's policies, 8 requests wide. An account with a few hundred roles audits in roughly a minute. Use `--role <name>` to audit one role during iteration.
- **Prompt-injection findings show `principal: unknown`.** Bedrock invocation logs do not carry caller identity. Correlate through the CloudTrail-sourced findings in the same report (`guardrail-less-invocation` and `off-hours-bedrock-usage` name the principal) or through CloudTrail event history for the same time window.
- **Off-hours detection is UTC-based.** The 22:00 to 06:00 UTC window and weekend check will misread workloads in other time zones. Treat those findings as prompts for review, not verdicts.
- **Findings are deterministic; Claude's commentary is not.** For canonical output, use the CLI with pinned `--region` and `--hours`, or read the HTML and JSON artifacts rather than the chat summary.

## Development

```bash
npm install
npm run build          # tsc
npm test               # vitest, no AWS access required
npm run build:catalog  # regenerate examples/rules-catalog.json from the rules
```

Unit tests run against committed JSON fixtures and never call AWS. The audit itself requires credentials only at runtime.

CI runs tests, the build, and `npm audit` on every pull request and push to main. Releases are published to npm from GitHub Actions via [Trusted Publishing](https://docs.npmjs.com/trusted-publishers/) (OIDC): no publish tokens exist, and every release carries a [SLSA provenance attestation](https://www.npmjs.com/package/bedrock-security-mcp#provenance) linking the npm package to the exact commit and workflow run that built it. Dependabot security updates are enabled.

## License

MIT
