// src/cli.ts

import { generateAiPostureReport } from "./tools/generate-posture-report.js";

interface CliArgs {
  region: string;
  roleName?: string;
  hoursBack?: number;
  outDir: string;
  title?: string;
  json: boolean;
}

/** Returns parsed args, "help" for an explicit -h/--help (exit 0), or null on bad args (exit 2). */
function parseArgs(argv: string[]): CliArgs | "help" | null {
  const args: CliArgs = {
    region: process.env.AWS_REGION ?? "us-east-1",
    outDir: process.env.BEDROCK_SECURITY_OUTPUT_DIR ?? ".",
    json: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--region":   args.region = argv[++i] ?? args.region; break;
      case "--role":     args.roleName = argv[++i]; break;
      case "--hours":    args.hoursBack = Number(argv[++i]); break;
      case "--out-dir":  args.outDir = argv[++i] ?? args.outDir; break;
      case "--title":    args.title = argv[++i]; break;
      case "--json":     args.json = true; break;
      case "-h": case "--help": printHelp(); return "help";
      default:
        console.error(`Unknown argument: ${a}`);
        printHelp();
        return null;
    }
  }
  return args;
}

function printHelp(): void {
  console.error(`bedrock-security-mcp audit — run a Bedrock security audit without an LLM

Usage: bedrock-security-mcp audit [options]

Options:
  --region <region>   AWS region (default: AWS_REGION or us-east-1)
  --role <roleName>   Audit a single IAM role only
  --hours <n>         Hours of CloudTrail/invocation-log history (default: 24, clamped to [1, 2160] = 90 days; CloudTrail's retention cap)
  --out-dir <path>    Directory to write the HTML report (default: current dir)
  --title <title>     Report title
  --json              Emit findings as JSON instead of markdown to stdout
  -h, --help          Show this help

Exit code: 0 if no critical- or high-severity FAIL findings, 1 if any present, 2 on bad args.
The MCP server (no args) is the interactive interface for Claude Desktop/Code.
`);
}

export async function runCli(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args === "help") return 0;
  if (!args) return 2;

  // Drive the report writer via env so HTML lands in the chosen dir.
  process.env.BEDROCK_SECURITY_OUTPUT_DIR = args.outDir;

  const input: { roleName?: string; hoursBack?: number; title?: string } = {};
  if (args.roleName)  input.roleName = args.roleName;
  if (args.hoursBack) input.hoursBack = args.hoursBack;
  if (args.title)     input.title = args.title;

  const result = await generateAiPostureReport(input, args.region);

  if (args.json) {
    console.log(JSON.stringify(result.findings, null, 2));
  } else {
    console.log(result.markdown);
  }
  if (result.htmlPath) {
    console.error(`HTML report written to ${result.htmlPath}`);
  }

  // CI gate: critical- or high-severity FAIL → non-zero exit. High is the blocker
  // tier for a security tool (e.g. bedrock-logging-disabled should block a deploy).
  const hasBlocking = result.findings.some(
    f => (f.severity === "critical" || f.severity === "high") && f.status === "FAIL"
  );
  return hasBlocking ? 1 : 0;
}
