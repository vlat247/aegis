import { AegisScanner } from "./scanner.js";
import { AegisScorer } from "./scorer.js";
import { AegisSanitizer } from "./sanitizer.js";
import { defaultRules } from "./rules.js";
import type {
  AegisFirewallOptions,
  AegisMode,
  AegisRule,
  AegisScanResult,
  FirewallAction,
  RetrievedContext,
  RiskLevel,
  ScanRequest,
  ToolDefinition
} from "./types.js";

export class AegisFirewallBlockedError extends Error {
  readonly result: AegisScanResult;

  constructor(result: AegisScanResult) {
    super("AegisFirewall blocked this prompt.");
    this.name = "AegisFirewallBlockedError";
    this.result = result;
  }
}

export class AegisFirewall {
  private readonly mode: AegisMode;
  private readonly riskThreshold: number;
  private readonly hasActionOverride: boolean;
  private readonly tools?: ToolDefinition[];
  private readonly retrievedContext?: RetrievedContext | RetrievedContext[];
  private readonly untrustedContext: boolean;
  private readonly scanner: AegisScanner;
  private readonly scorer: AegisScorer;
  private readonly sanitizer: AegisSanitizer;

  constructor(options: AegisFirewallOptions = {}) {
    this.mode = options.mode ?? "monitor";
    this.riskThreshold = options.riskThreshold ?? 75;
    this.hasActionOverride =
      options.mode !== undefined || options.riskThreshold !== undefined;
    this.tools = options.tools;
    this.retrievedContext = options.retrievedContext;
    this.untrustedContext = options.untrustedContext ?? false;
    this.scanner = new AegisScanner(options.rules ?? defaultRules);
    this.scorer = new AegisScorer();
    this.sanitizer = new AegisSanitizer();
  }

  scanText(prompt: string, request: Partial<ScanRequest> = {}): AegisScanResult {
    const findings = this.scanner.scan(prompt);
    const riskScore = this.scorer.score(findings, {
      input: prompt,
      tools: request.tools ?? this.tools,
      retrievedContext: request.retrievedContext ?? this.retrievedContext,
      untrustedContext: request.untrustedContext ?? this.untrustedContext
    });
    const riskLevel = getRiskLevel(riskScore);
    const action = getFirewallAction({
      hasActionOverride: this.hasActionOverride,
      mode: this.mode,
      riskLevel,
      riskScore,
      riskThreshold: this.riskThreshold
    });
    const blocked = action === "block";
    const safePrompt =
      action === "redact" ? this.sanitizer.sanitize(prompt, findings) : prompt;

    return {
      riskScore,
      riskLevel,
      action,
      allowed: !blocked,
      blocked,
      mode: this.mode,
      input: prompt,
      output: safePrompt,
      reasons: findings.map(
        (finding) => `${finding.ruleId}: ${finding.description}`
      ),
      matchedRules: findings,
      matchedRuleIds: findings.map((finding) => finding.ruleId),
      safePrompt,
      originalPrompt: prompt,
      riskThreshold: this.riskThreshold,
      findings
    };
  }

  scan(request: ScanRequest): AegisScanResult;
  scan(prompt: string): AegisScanResult;
  scan(input: ScanRequest | string): AegisScanResult {
    if (typeof input === "string") {
      return this.scanText(input);
    }

    const prompt = input.input ?? input.prompt;

    if (typeof prompt !== "string") {
      throw new TypeError("AegisFirewall.scan requires a prompt or input string.");
    }

    return this.scanText(prompt, input);
  }

  guard(prompt: string): string {
    const result = this.scanText(prompt);

    if (this.shouldBlock(result)) {
      throw new AegisFirewallBlockedError(result);
    }

    return result.safePrompt;
  }

  shouldBlock(result: AegisScanResult): boolean {
    return result.action === "block" || result.blocked;
  }
}

function getRiskLevel(riskScore: number): RiskLevel {
  if (riskScore >= 81) {
    return "critical";
  }

  if (riskScore >= 61) {
    return "high";
  }

  if (riskScore >= 31) {
    return "medium";
  }

  return "low";
}

function getFirewallAction({
  hasActionOverride,
  mode,
  riskLevel,
  riskScore,
  riskThreshold
}: {
  hasActionOverride: boolean;
  mode: AegisMode;
  riskLevel: RiskLevel;
  riskScore: number;
  riskThreshold: number;
}): FirewallAction {
  if (!hasActionOverride) {
    return getRiskLevelAction(riskLevel);
  }

  if (riskScore < riskThreshold) {
    return riskLevel === "low" ? "allow" : "warn";
  }

  if (mode === "block") {
    return "block";
  }

  if (mode === "redact" || mode === "sanitize") {
    return "redact";
  }

  return "warn";
}

function getRiskLevelAction(riskLevel: RiskLevel): FirewallAction {
  if (riskLevel === "critical") {
    return "block";
  }

  if (riskLevel === "high") {
    return "redact";
  }

  if (riskLevel === "medium") {
    return "warn";
  }

  return "allow";
}

export { AegisScanner } from "./scanner.js";
export { AegisScorer } from "./scorer.js";
export { AegisSanitizer } from "./sanitizer.js";
export { defaultRules } from "./rules.js";
export { wrapOpenAIClient } from "./openai-wrapper.js";
export type {
  AegisFinding,
  AegisFirewallOptions,
  AegisMode,
  AegisRuleCategory,
  AegisRule,
  AegisScanInput,
  AegisScanResult,
  AegisSeverity,
  AegisConfig,
  FirewallAction,
  OpenAIChatCompletionParams,
  OpenAIChatMessage,
  OpenAICompatibleClient,
  RiskLevel,
  Rule,
  RuleMatch,
  RetrievedContext,
  ScanRequest,
  ScanResult,
  ToolDefinition
} from "./types.js";
