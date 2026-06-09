import { defaultRules } from "./rules.js";
import type { AegisFinding, AegisRule } from "./types.js";

export class AegisScanner {
  private readonly rules: AegisRule[];

  constructor(rules: AegisRule[] = defaultRules) {
    this.rules = rules;
  }

  scan(input: string): AegisFinding[] {
    const findings: AegisFinding[] = [];

    for (const rule of this.rules) {
      const match = rule.pattern.exec(input);

      if (!match) {
        continue;
      }

      findings.push({
        ruleId: rule.id,
        description: rule.description,
        severity: rule.severity,
        score: rule.score,
        match: match[0],
        index: match.index
      });
    }

    return findings;
  }
}
