import type {
  AegisScanResult,
  OpenAIChatCompletionParams,
  OpenAIChatMessage,
  OpenAICompatibleClient
} from "./types.js";
import { AegisFirewall, AegisFirewallBlockedError } from "./index.js";

export interface AegisOpenAIWrapperOptions {
  firewall?: AegisFirewall;
  onBlocked?: (result: AegisScanResult) => void;
}

export function wrapOpenAIClient<TClient extends OpenAICompatibleClient>(
  client: TClient,
  options: AegisOpenAIWrapperOptions = {}
): TClient {
  const firewall = options.firewall ?? new AegisFirewall();

  return {
    ...client,
    chat: client.chat
      ? {
          ...client.chat,
          completions: client.chat.completions
            ? {
                ...client.chat.completions,
                create: async (params: OpenAIChatCompletionParams) => {
                  const scanResults: AegisScanResult[] = [];
                  const messages = params.messages ?? [];
                  const newMessages: OpenAIChatMessage[] = [];

                  for (const msg of messages) {
                    if (msg.role === "user") {
                      if (typeof msg.content === "string") {
                        const scanResult = firewall.scan(msg.content);
                        scanResults.push(scanResult);
                        if (!scanResult.allowed || firewall.shouldBlock(scanResult)) {
                          options.onBlocked?.(scanResult);
                          throw new AegisFirewallBlockedError(scanResult);
                        }
                        newMessages.push({
                          ...msg,
                          content: scanResult.safePrompt
                        });
                      } else if (Array.isArray(msg.content)) {
                        const newContentParts: any[] = [];
                        for (const part of msg.content) {
                          if (
                            part &&
                            typeof part === "object" &&
                            "text" in part &&
                            typeof part.text === "string"
                          ) {
                            const scanResult = firewall.scan(part.text);
                            scanResults.push(scanResult);
                            if (!scanResult.allowed || firewall.shouldBlock(scanResult)) {
                              options.onBlocked?.(scanResult);
                              throw new AegisFirewallBlockedError(scanResult);
                            }
                            newContentParts.push({
                              ...part,
                              text: scanResult.safePrompt
                            });
                          } else {
                            newContentParts.push(part);
                          }
                        }
                        newMessages.push({
                          ...msg,
                          content: newContentParts
                        });
                      } else {
                        newMessages.push(msg);
                      }
                    } else {
                      newMessages.push(msg);
                    }
                  }

                  const response = await client.chat!.completions!.create({
                    ...params,
                    messages: newMessages
                  });

                  if (response && typeof response === "object") {
                    Object.defineProperty(response, "aegis", {
                      value: {
                        scanResults,
                        allowed: true,
                        blocked: false,
                        findings: scanResults.flatMap((r) => r.findings),
                        riskScore: scanResults.length > 0 ? Math.max(...scanResults.map((r) => r.riskScore)) : 0
                      },
                      writable: true,
                      configurable: true,
                      enumerable: true
                    });
                  }

                  return response;
                }
              }
            : client.chat.completions
        }
      : client.chat,
    responses: client.responses
      ? {
          ...client.responses,
          create: async (params: OpenAIChatCompletionParams) => {
            const scanResults: AegisScanResult[] = [];
            let newInput: typeof params.input = params.input;

            if (typeof params.input === "string") {
              const scanResult = firewall.scan(params.input);
              scanResults.push(scanResult);
              if (!scanResult.allowed || firewall.shouldBlock(scanResult)) {
                options.onBlocked?.(scanResult);
                throw new AegisFirewallBlockedError(scanResult);
              }
              newInput = scanResult.safePrompt;
            } else if (Array.isArray(params.input)) {
              const updatedInput: unknown[] = [];
              for (const item of params.input) {
                if (typeof item === "string") {
                  const scanResult = firewall.scan(item);
                  scanResults.push(scanResult);
                  if (!scanResult.allowed || firewall.shouldBlock(scanResult)) {
                    options.onBlocked?.(scanResult);
                    throw new AegisFirewallBlockedError(scanResult);
                  }
                  updatedInput.push(scanResult.safePrompt);
                } else {
                  updatedInput.push(item);
                }
              }
              newInput = updatedInput;
            }

            const response = await client.responses!.create({
              ...params,
              input: newInput
            });

            if (response && typeof response === "object") {
              Object.defineProperty(response, "aegis", {
                value: {
                  scanResults,
                  allowed: true,
                  blocked: false,
                  findings: scanResults.flatMap((r) => r.findings),
                  riskScore: scanResults.length > 0 ? Math.max(...scanResults.map((r) => r.riskScore)) : 0
                },
                writable: true,
                configurable: true,
                enumerable: true
              });
            }

            return response;
          }
        }
      : client.responses
  } as TClient;
}

export { wrapOpenAIClient as wrapOpenAI };
