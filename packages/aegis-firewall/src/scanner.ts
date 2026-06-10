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
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(input);

      if (!match) {
        continue;
      }

      findings.push({
        rule,
        ruleId: rule.id,
        category: rule.category,
        description: rule.description,
        severity: rule.severity,
        recommendation: rule.recommendation,
        match: match[0],
        index: match.index
      });
    }

    return findings;
  }
}
