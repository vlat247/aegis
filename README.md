# aegis-firewall

TypeScript monorepo for `aegis-firewall`, a small SDK for scanning, scoring, and sanitizing LLM inputs before they reach a model provider.

## Workspaces

- `packages/aegis-firewall` - SDK package
- `examples/basic-node` - minimal Node usage
- `examples/openai-wrapper` - wrapper-style integration example

## Scripts

```sh
pnpm install
pnpm build
pnpm typecheck
pnpm clean
```

## Usage

```ts
import { AegisFirewall } from "aegis-firewall";

const aegis = new AegisFirewall({
  mode: "block",
  riskThreshold: 75
});
```
