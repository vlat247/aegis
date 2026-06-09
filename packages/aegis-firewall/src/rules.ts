import type { AegisRule } from "./types.js";

export const defaultRules: AegisRule[] = [
  {
    id: "prompt-injection-ignore-instructions",
    description: "Attempts to override or ignore prior instructions.",
    severity: "critical",
    pattern: /\b(ignore|forget|disregard)\b[\s\S]{0,80}\b(previous|prior|above|system|developer)\b[\s\S]{0,80}\b(instructions?|prompt|message)\b/i,
    score: 45
  },
  {
    id: "system-prompt-exfiltration",
    description: "Requests disclosure of hidden system or developer prompts.",
    severity: "critical",
    pattern: /\b(reveal|show|print|dump|leak|exfiltrate)\b[\s\S]{0,80}\b(system|developer|hidden|internal)\b[\s\S]{0,80}\b(prompt|message|instructions?)\b/i,
    score: 45
  },
  {
    id: "credential-exfiltration",
    description: "Requests secrets, credentials, tokens, or API keys.",
    severity: "high",
    pattern: /\b(api[_ -]?key|secret|token|password|credential|private[_ -]?key)\b/i,
    score: 35
  },
  {
    id: "jailbreak-roleplay",
    description: "Uses jailbreak framing to bypass model safety behavior.",
    severity: "high",
    pattern: /\b(jailbreak|dan mode|developer mode|god mode|unfiltered|uncensored)\b/i,
    score: 35
  },
  {
    id: "tool-abuse",
    description: "Attempts to coerce unauthorized tool or shell execution.",
    severity: "medium",
    pattern: /\b(run|execute|call)\b[\s\S]{0,60}\b(shell|terminal|command|tool|function)\b/i,
    score: 20
  }
];
