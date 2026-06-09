import type {
  AegisScanResult,
  OpenAIChatCompletionParams,
  OpenAICompatibleClient
} from "./types.js";
import { AegisFirewall } from "./index.js";

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
                  const checked = firewall.scan(extractText(params));

                  if (!checked.allowed) {
                    options.onBlocked?.(checked);
                    throw new Error("AegisFirewall blocked this OpenAI request.");
                  }

                  return client.chat?.completions?.create({
                    ...params,
                    messages: rewriteMessages(params, checked.output)
                  });
                }
              }
            : client.chat.completions
        }
      : client.chat,
    responses: client.responses
      ? {
          ...client.responses,
          create: async (params: OpenAIChatCompletionParams) => {
            const checked = firewall.scan(extractText(params));

            if (!checked.allowed) {
              options.onBlocked?.(checked);
              throw new Error("AegisFirewall blocked this OpenAI request.");
            }

            return client.responses?.create({
              ...params,
              input: typeof params.input === "string" ? checked.output : params.input
            });
          }
        }
      : client.responses
  } as TClient;
}

function extractText(params: OpenAIChatCompletionParams): string {
  if (typeof params.input === "string") {
    return params.input;
  }

  return (params.messages ?? [])
    .map((message) => {
      if (typeof message.content === "string") {
        return message.content;
      }

      if (Array.isArray(message.content)) {
        return message.content.map((part) => part.text ?? "").join("\n");
      }

      return "";
    })
    .join("\n");
}

function rewriteMessages(
  params: OpenAIChatCompletionParams,
  sanitizedText: string
): OpenAIChatCompletionParams["messages"] {
  if (!params.messages?.length) {
    return params.messages;
  }

  let lastTextIndex = -1;

  for (let index = params.messages.length - 1; index >= 0; index -= 1) {
    if (typeof params.messages[index]?.content === "string") {
      lastTextIndex = index;
      break;
    }
  }

  if (lastTextIndex === -1) {
    return params.messages;
  }

  return params.messages.map((message, index) =>
    index === lastTextIndex ? { ...message, content: sanitizedText } : message
  );
}
