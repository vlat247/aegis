import type { AegisFinding } from "./types.js";

const REDACTION = "[redacted]";

export class AegisSanitizer {
  sanitize(input: string, findings: AegisFinding[]): string {
    return findings
      .sort((a, b) => b.index - a.index)
      .reduce((output, finding) => {
        const before = output.slice(0, finding.index);
        const after = output.slice(finding.index + finding.match.length);
        return `${before}${REDACTION}${after}`;
      }, input);
  }
}
