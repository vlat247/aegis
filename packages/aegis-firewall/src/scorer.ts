import type {
  AegisFinding,
  RetrievedContext,
  ToolDefinition
} from "./types.js";

export interface ScoreOptions {
  input?: string;
  tools?: ToolDefinition[];
  retrievedContext?: RetrievedContext | RetrievedContext[];
  untrustedContext?: boolean;
}

const DANGEROUS_TOOL_PATTERN =
  /\b(shell|exec|execute|command|terminal|bash|zsh|powershell|cmd|spawn|process|filesystem|file|write|delete|remove|rm|chmod|chown|network|http|fetch|request|curl|wget|webhook|database|sql|query)\b/i;

const OBFUSCATION_PATTERN =
  /[\u200B-\u200D\uFEFF]|\\u[0-9a-f]{4}|%[0-9a-f]{2}|(?:[A-Za-z0-9+/]{40,}={0,2})|\b(base64|b64|rot13|hex|unicode escape|url[- ]?decode|zero[- ]?width|invisible text)\b/i;

export class AegisScorer {
  score(findings: AegisFinding[], options: ScoreOptions = {}): number {
    const highestSeverity = findings.reduce(
      (highest, finding) => Math.max(highest, finding.severity),
      0
    );
    const matchedRuleBonus = Math.min(20, Math.max(0, findings.length - 1) * 8);
    const dangerousToolBonus = hasDangerousTool(options.tools) ? 15 : 0;
    const obfuscationBonus = hasObfuscationIndicator(findings, options.input) ? 12 : 0;
    const untrustedContextBonus = hasUntrustedContext(
      options.retrievedContext,
      options.untrustedContext
    )
      ? 10
      : 0;

    return clampScore(
      highestSeverity +
        matchedRuleBonus +
        dangerousToolBonus +
        obfuscationBonus +
        untrustedContextBonus
    );
  }
}

function hasDangerousTool(tools: ToolDefinition[] = []): boolean {
  return tools.some((tool) =>
    DANGEROUS_TOOL_PATTERN.test(
      [
        tool.name,
        tool.description,
        JSON.stringify(tool.parameters ?? {})
      ]
        .filter(Boolean)
        .join(" ")
    )
  );
}

function hasObfuscationIndicator(
  findings: AegisFinding[],
  input = ""
): boolean {
  return (
    findings.some((finding) => finding.category === "obfuscation") ||
    OBFUSCATION_PATTERN.test(input)
  );
}

function hasUntrustedContext(
  retrievedContext: RetrievedContext | RetrievedContext[] | undefined,
  untrustedContext = false
): boolean {
  if (untrustedContext) {
    return true;
  }

  const contexts = Array.isArray(retrievedContext)
    ? retrievedContext
    : retrievedContext
      ? [retrievedContext]
      : [];

  return contexts.some((context) => {
    const trust = context.metadata?.trust ?? context.metadata?.trusted;
    return (
      context.untrusted === true ||
      context.trusted === false ||
      trust === false ||
      trust === "false" ||
      trust === "untrusted"
    );
  });
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}
