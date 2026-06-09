import type { AegisFinding } from "./types.js";

export class AegisScorer {
  score(findings: AegisFinding[]): number {
    const total = findings.reduce((sum, finding) => sum + finding.score, 0);
    return Math.min(100, total);
  }
}
