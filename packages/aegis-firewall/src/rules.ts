import type { AegisRule } from "./types.js";

export const defaultRules: AegisRule[] = [
  {
    id: "instruction-override-ignore-prior",
    category: "instruction_override",
    severity: 92,
    description: "Attempts to ignore, forget, or disregard higher-priority instructions.",
    pattern: /\b(ignore|forget|disregard|bypass|override)\b[\s\S]{0,80}\b(previous|prior|above|earlier|system|developer)\b[\s\S]{0,80}\b(instructions?|prompts?|messages?|rules?)\b/i,
    recommendation: "Reject or isolate the prompt and preserve the configured instruction hierarchy."
  },
  {
    id: "instruction-override-new-role",
    category: "instruction_override",
    severity: 84,
    description: "Tries to replace the assistant role or operating instructions.",
    pattern: /\b(from now on|for the rest of (this )?(chat|conversation)|you are now|act as my new)\b[\s\S]{0,80}\b(system|developer|assistant|controller|operator|policy)\b/i,
    recommendation: "Treat role-change requests as untrusted user content and continue with the original role."
  },
  {
    id: "instruction-override-priority-claim",
    category: "instruction_override",
    severity: 78,
    description: "Claims the user message has higher authority than system or developer instructions.",
    pattern: /\b(this|my|the following)\b[\s\S]{0,50}\b(instruction|message|prompt|request)\b[\s\S]{0,80}\b(has|takes|is)\b[\s\S]{0,50}\b(priority|precedence|highest authority|superior)\b/i,
    recommendation: "Do not honor claimed priority changes from user-controlled text."
  },
  {
    id: "instruction-override-conflict-resolution",
    category: "instruction_override",
    severity: 74,
    description: "Instructs the model to resolve conflicts in favor of the user prompt.",
    pattern: /\b(if|when)\b[\s\S]{0,60}\b(conflict|contradict|disagree)\b[\s\S]{0,80}\b(system|developer|policy|instructions?)\b[\s\S]{0,80}\b(follow|obey|prefer|choose)\b[\s\S]{0,40}\b(user|me|this prompt)\b/i,
    recommendation: "Keep system and developer instructions authoritative during conflict resolution."
  },
  {
    id: "system-prompt-reveal",
    category: "system_prompt_extraction",
    severity: 95,
    description: "Requests disclosure of hidden system, developer, or internal prompts.",
    pattern: /\b(reveal|show|print|display|dump|leak|repeat|output)\b[\s\S]{0,80}\b(system|developer|hidden|internal|initial)\b[\s\S]{0,80}\b(prompt|message|instructions?|rules?)\b/i,
    recommendation: "Refuse to expose hidden instructions and provide a brief safety-preserving response."
  },
  {
    id: "system-prompt-verbatim",
    category: "system_prompt_extraction",
    severity: 90,
    description: "Asks for exact or verbatim policy or instruction text.",
    pattern: /\b(verbatim|exact|full|complete|word[- ]?for[- ]?word)\b[\s\S]{0,80}\b(system|developer|policy|hidden|internal)\b[\s\S]{0,80}\b(text|prompt|instructions?|message)\b/i,
    recommendation: "Avoid quoting hidden content; summarize only public behavior if appropriate."
  },
  {
    id: "system-prompt-debug-dump",
    category: "system_prompt_extraction",
    severity: 86,
    description: "Uses debugging or diagnostics framing to extract hidden instructions.",
    pattern: /\b(debug|diagnostic|developer|maintenance|audit|transparency)\b[\s\S]{0,80}\b(mode|view|dump|log|trace)\b[\s\S]{0,80}\b(prompt|instructions?|system|developer)\b/i,
    recommendation: "Do not expose internal diagnostics or instruction traces to user-controlled prompts."
  },
  {
    id: "secret-exfiltration-api-key",
    category: "secret_exfiltration",
    severity: 94,
    description: "Requests API keys, tokens, credentials, or private keys.",
    pattern: /\b(api[_ -]?key|access[_ -]?token|auth[_ -]?token|bearer token|secret|password|credential|private[_ -]?key|ssh[_ -]?key)\b/i,
    recommendation: "Block the request and ensure secrets are never sent to the model context."
  },
  {
    id: "secret-exfiltration-env",
    category: "secret_exfiltration",
    severity: 88,
    description: "Attempts to access environment variables or secret stores.",
    pattern: /\b(env|environment variables?|process\.env|\.env|secrets? manager|vault|keychain|kms)\b[\s\S]{0,80}\b(print|dump|show|list|read|exfiltrate|send)\b/i,
    recommendation: "Prevent access to environment data and redact any accidental secret-like values."
  },
  {
    id: "secret-exfiltration-config",
    category: "secret_exfiltration",
    severity: 82,
    description: "Requests sensitive configuration files or deployment secrets.",
    pattern: /\b(read|open|show|dump|cat)\b[\s\S]{0,80}\b(\.npmrc|\.pypirc|\.netrc|id_rsa|config\.json|credentials|service[-_ ]?account|kubeconfig)\b/i,
    recommendation: "Deny file disclosure requests for sensitive configuration paths."
  },
  {
    id: "tool-abuse-shell-execution",
    category: "tool_abuse",
    severity: 89,
    description: "Attempts to coerce unauthorized shell, terminal, or command execution.",
    pattern: /\b(run|execute|spawn|invoke|call)\b[\s\S]{0,60}\b(shell|terminal|bash|zsh|cmd|powershell|command)\b/i,
    recommendation: "Require explicit tool authorization and sandbox validation before executing commands."
  },
  {
    id: "tool-abuse-network-request",
    category: "tool_abuse",
    severity: 83,
    description: "Attempts to make tools send data to an external network destination.",
    pattern: /\b(curl|wget|fetch|post|http request|webhook|send request)\b[\s\S]{0,100}\b(http|https|ftp):\/\/[^\s]+/i,
    recommendation: "Block untrusted outbound requests unless destination and payload are approved."
  },
  {
    id: "tool-abuse-file-mutation",
    category: "tool_abuse",
    severity: 78,
    description: "Attempts destructive or unauthorized file operations through tools.",
    pattern: /\b(delete|remove|overwrite|chmod|chown|rm\s+-rf|format|wipe)\b[\s\S]{0,80}\b(file|folder|directory|disk|repo|workspace|home)\b/i,
    recommendation: "Require user confirmation and path-scoped authorization before mutating files."
  },
  {
    id: "data-exfiltration-upload",
    category: "data_exfiltration",
    severity: 88,
    description: "Requests uploading or forwarding local data to a third party.",
    pattern: /\b(upload|send|forward|post|exfiltrate|transmit)\b[\s\S]{0,100}\b(files?|documents?|data|database|logs?|workspace|conversation)\b[\s\S]{0,80}\b(to|via|using)\b/i,
    recommendation: "Do not transmit user or workspace data to external destinations without approval."
  },
  {
    id: "data-exfiltration-conversation",
    category: "data_exfiltration",
    severity: 76,
    description: "Requests disclosure of conversation history or private context.",
    pattern: /\b(show|dump|export|send|summarize)\b[\s\S]{0,80}\b(conversation history|chat history|prior messages|hidden context|memory|scratchpad)\b/i,
    recommendation: "Limit responses to user-visible context and avoid exposing private memory or hidden state."
  },
  {
    id: "data-exfiltration-database",
    category: "data_exfiltration",
    severity: 84,
    description: "Attempts to dump database records, customer data, or logs.",
    pattern: /\b(dump|export|select all|download|copy)\b[\s\S]{0,80}\b(database|db|users?|customers?|pii|logs?|records?|table)\b/i,
    recommendation: "Enforce data access controls and minimize any returned records."
  },
  {
    id: "obfuscation-base64",
    category: "obfuscation",
    severity: 68,
    description: "Uses base64 or encoding instructions to hide prompt content.",
    pattern: /\b(base64|b64|decode|encode|rot13|hex|unicode escape|url[- ]?decode)\b[\s\S]{0,100}\b(instruction|prompt|payload|message|command)\b/i,
    recommendation: "Decode and rescan content before processing, or reject opaque encoded payloads."
  },
  {
    id: "obfuscation-typoglycemia",
    category: "obfuscation",
    severity: 58,
    description: "Uses spaced, separated, or disguised instruction keywords.",
    pattern: /\b(i\s*g\s*n\s*o\s*r\s*e|d\s*i\s*s\s*r\s*e\s*g\s*a\s*r\s*d|o\s*v\s*e\s*r\s*r\s*i\s*d\s*e|j\s*a\s*i\s*l\s*b\s*r\s*e\s*a\s*k)\b/i,
    recommendation: "Normalize suspicious text variants and rescan for policy bypass attempts."
  },
  {
    id: "obfuscation-hidden-text",
    category: "obfuscation",
    severity: 64,
    description: "References hidden, invisible, or steganographic instructions.",
    pattern: /\b(hidden|invisible|white text|zero[- ]?width|steganographic|metadata|alt text)\b[\s\S]{0,80}\b(instructions?|prompt|payload|message|command)\b/i,
    recommendation: "Extract visible and hidden text channels, normalize them, and scan together."
  },
  {
    id: "jailbreak-dan",
    category: "jailbreak",
    severity: 91,
    description: "Invokes known jailbreak personas or unrestricted modes.",
    pattern: /\b(DAN|do anything now|developer mode|god mode|evil mode|unfiltered mode|uncensored mode)\b/i,
    recommendation: "Refuse jailbreak framing and continue under the configured safety policy."
  },
  {
    id: "jailbreak-policy-bypass",
    category: "jailbreak",
    severity: 87,
    description: "Asks the model to bypass, disable, or ignore safety policy.",
    pattern: /\b(bypass|disable|turn off|ignore|circumvent)\b[\s\S]{0,80}\b(safety|policy|guardrails?|filters?|moderation|restrictions?)\b/i,
    recommendation: "Do not comply with policy bypass requests; answer within the allowed policy."
  },
  {
    id: "jailbreak-fictional-framing",
    category: "jailbreak",
    severity: 72,
    description: "Uses fictional, hypothetical, or roleplay framing to evade restrictions.",
    pattern: /\b(pretend|roleplay|fictional|hypothetical|for a story|simulation)\b[\s\S]{0,100}\b(no rules|no restrictions|illegal|forbidden|bypass|uncensored)\b/i,
    recommendation: "Apply the same safety checks to fictional or hypothetical requests."
  },
  {
    id: "unsafe-delegation-untrusted-output",
    category: "unsafe_delegation",
    severity: 79,
    description: "Tells the model to follow instructions from untrusted external content.",
    pattern: /\b(read|fetch|open|parse|visit)\b[\s\S]{0,80}\b(url|website|page|email|document|pdf|file)\b[\s\S]{0,100}\b(follow|obey|execute|do what it says|instructions? inside)\b/i,
    recommendation: "Treat retrieved content as data and never delegate authority to it."
  },
  {
    id: "unsafe-delegation-agent-chain",
    category: "unsafe_delegation",
    severity: 73,
    description: "Attempts to delegate decisions to another agent or model without constraints.",
    pattern: /\b(ask|call|delegate to|handoff to)\b[\s\S]{0,80}\b(agent|model|assistant|bot|tool)\b[\s\S]{0,100}\b(without asking|without confirmation|automatically|autonomously|whatever it says)\b/i,
    recommendation: "Require bounded tool permissions and human confirmation for delegated actions."
  },
  {
    id: "unsafe-delegation-permission-transfer",
    category: "unsafe_delegation",
    severity: 81,
    description: "Tries to transfer user or system permissions to untrusted instructions.",
    pattern: /\b(grant|give|transfer|inherit|assume)\b[\s\S]{0,80}\b(permission|authority|access|credentials?|privileges?)\b[\s\S]{0,80}\b(to|from)\b[\s\S]{0,80}\b(prompt|document|website|tool|agent)\b/i,
    recommendation: "Keep permissions bound to explicit user approvals and trusted system configuration."
  }
];
