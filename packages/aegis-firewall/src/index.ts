import { AegisScanner } from "./scanner.js";
import { AegisScorer } from "./scorer.js";
import { AegisSanitizer } from "./sanitizer.js";
import { defaultRules } from "./rules.js";
import type {
  AegisFirewallOptions,
  AegisMode,
  AegisRule,
  AegisScanResult
} from "./types.js";

export class AegisFirewall {
  private readonly mode: AegisMode;
  private readonly riskThreshold: number;
  private readonly scanner: AegisScanner;
  private readonly scorer: AegisScorer;
  private readonly sanitizer: AegisSanitizer;

  constructor(options: AegisFirewallOptions = {}) {
    this.mode = options.mode ?? "monitor";
    this.riskThreshold = options.riskThreshold ?? 75;
    this.scanner = new AegisScanner(options.rules ?? defaultRules);
    this.scorer = new AegisScorer();
    this.sanitizer = new AegisSanitizer();
  }

  scan(input: string): AegisScanResult {
    const findings = this.scanner.scan(input);
    const riskScore = this.scorer.score(findings);
    const blocked = this.mode === "block" && riskScore >= this.riskThreshold;
    const output =
      this.mode === "sanitize" && riskScore >= this.riskThreshold
        ? this.sanitizer.sanitize(input, findings)
        : input;

    return {
      allowed: !blocked,
      blocked,
      mode: this.mode,
      input,
      output,
      riskScore,
      riskThreshold: this.riskThreshold,
      findings
    };
  }
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
  AegisRule,
  AegisScanInput,
  AegisScanResult,
  AegisSeverity,
  OpenAIChatCompletionParams,
  OpenAIChatMessage,
  OpenAICompatibleClient
} from "./types.js";
