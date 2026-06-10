import type { AegisFinding } from "./types.js";

const REDACTION = "[redacted]";

// Regex for hidden Unicode characters
// Targets:
// - Zero-width spaces, joiners, markers: \u200B-\u200D, \uFEFF, \u200E, \u200F
// - Direction override characters: \u202A-\u202E
// - Invisible operators and isolates: \u2060-\u206F
// - Soft hyphen: \u00AD
// - Tag characters (steganographic unicode): \u{E0000}-\u{E007F}
const HIDDEN_UNICODE_REGEX = /[\u200B-\u200D\u200E\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD]|[\u{E0000}-\u{E007F}]/gu;

/**
 * Removes hidden unicode characters.
 */
export function sanitizeHiddenUnicode(input: string): string {
  return input.replace(HIDDEN_UNICODE_REGEX, "");
}

const HTML_COMMENT_REGEX = /<!--[\s\S]*?-->/g;

/**
 * Removes HTML comments.
 */
export function sanitizeHtmlComments(input: string): string {
  return input.replace(HTML_COMMENT_REGEX, "");
}

// Matches markdown links where the bracket is empty or consists only of whitespace/hidden chars:
// - Inline style: [   ](url)
// - Reference style: [   ][ref]
const MD_HIDDEN_LINK_REGEX = /\[[\s\u200B-\u200D\u200E\u200F\uFEFF\u00AD]*\]\([^)]*\)/g;
const MD_HIDDEN_REF_LINK_REGEX = /\[[\s\u200B-\u200D\u200E\u200F\uFEFF\u00AD]*\]\[[^\]]*\]/g;

/**
 * Removes markdown hidden links.
 */
export function sanitizeMarkdownHiddenLinks(input: string): string {
  return input
    .replace(MD_HIDDEN_LINK_REGEX, "")
    .replace(MD_HIDDEN_REF_LINK_REGEX, "");
}

// Matches patterns asking for disclosure of system prompt, hidden prompt, verbatim text, etc.
const SYSTEM_PROMPT_EXTRACTION_PATTERNS = [
  /\b(reveal|show|print|display|dump|leak|repeat|output)\b[\s\S]{0,80}\b(system|developer|hidden|internal|initial)\b[\s\S]{0,80}\b(prompt|message|instructions?|rules?)/i,
  /\b(verbatim|exact|full|complete|word[- ]?for[- ]?word)\b[\s\S]{0,80}\b(system|developer|policy|hidden|internal)\b[\s\S]{0,80}\b(text|prompt|instructions?|message)/i,
  /\b(debug|diagnostic|developer|maintenance|audit|transparency)\b[\s\S]{0,80}\b(mode|view|dump|log|trace)\b[\s\S]{0,80}\b(prompt|instructions?|system|developer)/i,
  /\b(leak|reveal|output)\b[\s\S]{0,50}\b(your|the)\b[\s\S]{0,50}\b(system prompt|initial instructions)/i,
  /\b(what are your)\b[\s\S]{0,50}\b(system instructions|initial instructions|system prompts)/i
];

/**
 * Neutralizes system prompt extraction attempts by redacting them.
 */
export function sanitizeSystemPromptExtraction(input: string): string {
  let result = input;
  for (const pattern of SYSTEM_PROMPT_EXTRACTION_PATTERNS) {
    result = result.replace(pattern, "[system prompt request redacted]");
  }
  return result;
}

// Matches strings of base64 characters of length 16+ ending with optional '=' padding.
const BASE64_CANDIDATE_REGEX = /[A-Za-z0-9+/]{16,}={0,2}/g;

/**
 * Neutralizes suspicious base64 payloads that decode to instructions or binary.
 */
export function sanitizeBase64Suspicious(input: string): string {
  return input.replace(BASE64_CANDIDATE_REGEX, (match) => {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      
      // Keywords that indicate instruction override or safety bypass
      const suspiciousKeywords = /\b(ignore|forget|disregard|bypass|override|system|prompt|rule|instruction|secret|reveal|leak|role|assistant|policy|developer|jailbreak)\b/i;
      
      if (suspiciousKeywords.test(decoded)) {
        return "[suspicious base64 redacted]";
      }
      
      // Check for non-printable binary-like payload
      const printableRegex = /^[\x20-\x7E\r\n\t]*$/;
      if (!printableRegex.test(decoded)) {
        return "[suspicious base64 redacted]";
      }
    } catch {
      // If base64 decoding fails or isn't valid UTF-8, preserve it
      return match;
    }
    return match;
  });
}

/**
 * Removes or neutralizes repeated instruction override phrases.
 */
export function sanitizeRepeatedOverridePhrases(input: string): string {
  // 1. Collapse consecutive identical override words (e.g. "ignore ignore ignore")
  let output = input.replace(
    /\b(ignore|forget|disregard|bypass|override|jailbreak)\b([\s,;.-]+\b\1\b)+/gi,
    "[repeated instruction override redacted]"
  );

  // 2. Split into sentences/clauses to check for repeated/duplicate override phrases
  const sentences = output.split(/([\n.!?;\u2028\u2029]+)/);
  const overrideKeywords = /\b(ignore|forget|disregard|bypass|override|jailbreak)\b/i;
  
  const analyzed: { text: string; normalized: string; index: number }[] = [];
  
  for (let i = 0; i < sentences.length; i++) {
    // If it's a delimiter, i is odd (since we use a capture group in split)
    if (i % 2 === 1) {
      continue;
    }
    const txt = sentences[i];
    const trimmed = txt.trim();
    if (trimmed.length === 0) {
      continue;
    }
    
    // Only analyze clauses that contain override keywords
    if (overrideKeywords.test(trimmed)) {
      const normalized = trimmed
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, "")
        .trim();
      analyzed.push({ text: txt, normalized, index: i });
    }
  }
  
  const indicesToRemove = new Set<number>();
  
  for (let i = 0; i < analyzed.length; i++) {
    const current = analyzed[i];
    for (let j = i + 1; j < analyzed.length; j++) {
      const other = analyzed[j];
      
      const words1 = current.normalized.split(/\s+/).filter(Boolean);
      const words2 = other.normalized.split(/\s+/).filter(Boolean);
      
      const set1 = new Set(words1);
      const set2 = new Set(words2);
      const intersection = new Set([...set1].filter(x => set2.has(x)));
      const union = new Set([...set1, ...set2]);
      
      const similarity = union.size > 0 ? intersection.size / union.size : 0;
      
      // Flag if they are highly similar or one contains another as a substring
      const isSubstring =
        current.normalized.includes(other.normalized) ||
        other.normalized.includes(current.normalized);
        
      if (similarity >= 0.5 || isSubstring) {
        indicesToRemove.add(current.index);
        indicesToRemove.add(other.index);
      }
    }
  }
  
  if (indicesToRemove.size > 0) {
    const rebuilt: string[] = [];
    for (let i = 0; i < sentences.length; i++) {
      if (indicesToRemove.has(i)) {
        const txt = sentences[i];
        const matchWhitespace = txt.match(/^(\s*)([\s\S]*?)(\s*)$/);
        const leadingWs = matchWhitespace ? matchWhitespace[1] : "";
        const trailingWs = matchWhitespace ? matchWhitespace[3] : "";
        rebuilt.push(`${leadingWs}[repeated instruction override redacted]${trailingWs}`);
      } else {
        rebuilt.push(sentences[i]);
      }
    }
    output = rebuilt.join("");
  }
  
  return output;
}

export class AegisSanitizer {
  sanitize(input: string, findings: AegisFinding[] = []): string {
    // 1. First, apply findings-based redaction if findings are provided
    let output = input;
    if (findings && findings.length > 0) {
      output = findings
        .sort((a, b) => b.index - a.index)
        .reduce((current, finding) => {
          const before = current.slice(0, finding.index);
          const after = current.slice(finding.index + finding.match.length);
          return `${before}${REDACTION}${after}`;
        }, output);
    }

    // 2. Chain all pure sanitization rules
    output = sanitizeHiddenUnicode(output);
    output = sanitizeHtmlComments(output);
    output = sanitizeMarkdownHiddenLinks(output);
    output = sanitizeRepeatedOverridePhrases(output);
    output = sanitizeSystemPromptExtraction(output);
    output = sanitizeBase64Suspicious(output);

    return output;
  }
}
