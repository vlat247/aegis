export type AegisMode = "monitor" | "sanitize" | "redact" | "block";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type AegisRuleCategory =
  | "instruction_override"
  | "system_prompt_extraction"
  | "secret_exfiltration"
  | "tool_abuse"
  | "data_exfiltration"
  | "obfuscation"
  | "jailbreak"
  | "unsafe_delegation";

export type AegisSeverity = number;

export type FirewallAction = "allow" | "warn" | "redact" | "block";

export interface ToolDefinition {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  strict?: boolean;
  [key: string]: unknown;
}

export interface RetrievedContext {
  content?: string;
  source?: string;
  untrusted?: boolean;
  trusted?: boolean;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface Rule {
  id: string;
  category: AegisRuleCategory;
  severity: AegisSeverity;
  description: string;
  pattern: RegExp;
  recommendation: string;
}

export interface RuleMatch {
  rule: Rule;
  ruleId: string;
  category: AegisRuleCategory;
  description: string;
  severity: AegisSeverity;
  recommendation: string;
  match: string;
  index: number;
}

export interface AegisConfig {
  mode?: AegisMode;
  riskThreshold?: number;
  rules?: Rule[];
  tools?: ToolDefinition[];
  retrievedContext?: RetrievedContext | RetrievedContext[];
  untrustedContext?: boolean;
}

export interface ScanRequest {
  input?: string;
  prompt?: string;
  tools?: ToolDefinition[];
  retrievedContext?: RetrievedContext | RetrievedContext[];
  untrustedContext?: boolean;
}

export interface ScanResult {
  riskScore: number;
  riskLevel: RiskLevel;
  action: FirewallAction;
  allowed: boolean;
  blocked: boolean;
  mode: AegisMode;
  input: string;
  output: string;
  reasons: string[];
  matchedRules: RuleMatch[];
  matchedRuleIds: string[];
  safePrompt: string;
  originalPrompt: string;
  riskThreshold: number;
  findings: RuleMatch[];
}

export type AegisRule = Rule;

export type AegisFinding = RuleMatch;

export type AegisFirewallOptions = AegisConfig;

export type AegisScanInput = ScanRequest;

export type AegisScanResult = ScanResult;

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
