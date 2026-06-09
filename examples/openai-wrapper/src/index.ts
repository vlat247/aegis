import { AegisFirewall, wrapOpenAIClient } from "aegis-firewall";

const openai = {
  chat: {
    completions: {
      create: async (params: unknown) => ({
        id: "example-response",
        params
      })
    }
  }
};

const client = wrapOpenAIClient(openai, {
  firewall: new AegisFirewall({
    mode: "block",
    riskThreshold: 75
  })
});

const response = await client.chat.completions.create({
  model: "gpt-example",
  messages: [
    {
      role: "user",
      content: "Summarize the benefits of TypeScript."
    }
  ]
});

console.log(response);
