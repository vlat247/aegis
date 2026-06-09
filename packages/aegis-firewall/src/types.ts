export type AegisMode = "monitor" | "sanitize" | "block";

export type AegisSeverity = "low" | "medium" | "high" | "critical";

export interface AegisRule {
  id: string;
  description: string;
  severity: AegisSeverity;
  pattern: RegExp;
  score: number;
}

export interface AegisFinding {
  ruleId: string;
  description: string;
  severity: AegisSeverity;
  score: number;
  match: string;
  index: number;
}

export interface AegisFirewallOptions {
  mode?: AegisMode;
  riskThreshold?: number;
  rules?: AegisRule[];
}

export interface AegisScanInput {
  input: string;
}

export interface AegisScanResult {
  allowed: boolean;
  blocked: boolean;
  mode: AegisMode;
  input: string;
  output: string;
  riskScore: number;
  riskThreshold: number;
  findings: AegisFinding[];
}

export interface OpenAIChatMessage {
  role: string;
  content?: string | Array<{ type: string; text?: string }> | null;
  [key: string]: unknown;
}

export interface OpenAIChatCompletionParams {
  messages?: OpenAIChatMessage[];
  input?: string | unknown[];
  [key: string]: unknown;
}

export interface OpenAICompatibleClient {
  chat?: {
    completions?: {
      create(params: OpenAIChatCompletionParams): Promise<unknown>;
    };
  };
  responses?: {
    create(params: OpenAIChatCompletionParams): Promise<unknown>;
  };
}
