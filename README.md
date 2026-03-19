# crypto-key-guard

Detect, redact, and block crypto private keys and seed phrases in text. Prevent sensitive secrets from leaking to LLMs, AI agents, logs, and external services.

**Zero dependencies. Regex-based. Runs in < 1ms.**

## Why?

AI agents and LLMs are increasingly used in crypto/Web3 applications. Users accidentally (or intentionally) paste private keys and seed phrases into chat. These messages get sent to LLM providers (OpenAI, Anthropic, Google) — exposing wallet secrets to third parties.

`crypto-key-guard` sits between user input and your LLM, detecting and blocking crypto secrets before they leave your system.

## Supported Chains

| Chain                                                           | Private Key Format             | Curve     | Detection        |
| --------------------------------------------------------------- | ------------------------------ | --------- | ---------------- |
| **Solana**                                                      | Base58, 87-88 characters       | ed25519   | Yes              |
| **EVM (Ethereum, BSC, Polygon, Arbitrum, Base, Optimism, ...)** | 0x + 64 hex characters         | secp256k1 | Yes              |
| **Aptos**                                                       | 0x + 64 hex characters         | ed25519   | Yes              |
| **Sui**                                                         | 0x + 64 hex characters         | ed25519   | Yes              |
| **Bitcoin**                                                     | WIF format (starts with 5/K/L) | secp256k1 | Yes              |
| **BIP39 Seed Phrases**                                          | 12 or 24 words                 | —         | Yes (all chains) |

## Install

```bash
npm install crypto-key-guard
```

## Quick Start

### Block messages containing secrets

```typescript
import { guard } from "crypto-key-guard";

const userMessage =
  "use this key 0x4c0883a69102937d6231471b5dbb6204fe512961708279f3e5a1b0d5e8f2a5b1";

const result = guard(userMessage);

if (result.detected) {
  // DO NOT send to LLM
  console.warn(result.message);
  // "Blocked: detected 1 crypto secret(s) in text: EVM/Aptos/Sui Private Key.
  //  This message was NOT sent to the AI provider. Never share your private keys or seed phrases."
  return;
}

// Safe — send to LLM
sendToLLM(userMessage);
```

### Redact secrets before sending to LLM, restore after

```typescript
import { redact, restore } from "crypto-key-guard";

const userMessage =
  "run workflow with key 0x4c0883a69102937d6231471b5dbb6204fe512961708279f3e5a1b0d5e8f2a5b1";

// Redact before sending to LLM
const { text, secrets } = redact(userMessage);
// text: "run workflow with key [EVM_KEY_1]"
// secrets: Map { "[EVM_KEY_1]" => "0x4c08..." }

const llmResponse = await sendToLLM(text);
// LLM never sees the real key

// Restore when you need the actual value
const restored = restore(llmResponse, secrets);
```

### Detect secrets with details

```typescript
import { detect } from "crypto-key-guard";

const findings = detect(
  "my solana key is 4wBqpZM9msxygKxGzHYV5mGDrEULFnPGxFkQR3grRKAVchxbPFJNS9bSEHvPpPUFhEigmMbPB9SnCFDYEYPk6FaE",
);

// [{
//   type: "solana_private_key",
//   label: "Solana Private Key",
//   value: "4wBqpZM9...",
//   start: 17,
//   end: 105
// }]
```

### Simple checks

```typescript
import { isPrivateKey, isSeedPhrase, containsSecret } from "crypto-key-guard";

isPrivateKey(
  "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3e5a1b0d5e8f2a5b1",
);
// true

isSeedPhrase(
  "abandon ability able about above absent absorb abstract absurd abuse access accident",
);
// true

containsSecret("just a normal message");
// false
```

## API

### `guard(text: string): GuardResult`

Check text and return a blocking result if secrets are found.

```typescript
type GuardResult = {
  detected: boolean; // true if any secrets found
  findings: Finding[]; // details of each secret
  message: string; // human-readable warning
};
```

### `detect(text: string): Finding[]`

Detect all crypto secrets in text with position information.

```typescript
type Finding = {
  type: SecretType; // "solana_private_key" | "evm_private_key" | "bitcoin_wif" | "seed_phrase_12" | "seed_phrase_24"
  label: string; // human-readable label
  value: string; // the detected secret
  start: number; // start index in text
  end: number; // end index in text
};
```

### `redact(text: string): RedactResult`

Replace secrets with safe tokens. Returns a map to restore originals.

```typescript
type RedactResult = {
  text: string; // text with secrets replaced by tokens
  secrets: Map<string, string>; // token → original value
  findings: Finding[]; // all findings
};
```

### `restore(text: string, secrets: Map<string, string>): string`

Restore redacted tokens back to original values.

### `isPrivateKey(value: string): boolean`

Check if a string is a crypto private key.

### `isSeedPhrase(value: string): boolean`

Check if a string is a BIP39 seed phrase (12 or 24 words).

### `containsSecret(value: string): boolean`

Check if a string is either a private key or seed phrase.

## Use Cases

### AI Agent / LLM Gateway

Prevent user secrets from reaching LLM providers:

```typescript
import { guard, redact, restore } from "crypto-key-guard";

const handleUserMessage = (message: string) => {
  // Option 1: Block entirely
  const check = guard(message);
  if (check.detected) {
    return check.message; // warn user, don't send to LLM
  }

  // Option 2: Redact, send safe version, restore in tool
  const { text, secrets } = redact(message);
  const response = await llm.invoke(text);
  return restore(response, secrets);
};
```

### Express Middleware

Strip secrets from all API responses:

```typescript
import { redact } from "crypto-key-guard";

app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    const { text } = redact(JSON.stringify(body));
    return originalJson(JSON.parse(text));
  };
  next();
});
```

### Input Validation

Block forms or chat inputs containing secrets:

```typescript
import { containsSecret } from "crypto-key-guard";

const onSubmit = (input: string) => {
  if (containsSecret(input)) {
    alert("Never paste your private key or seed phrase here!");
    return;
  }
  // proceed
};
```

## Performance

All detection runs in-process with regex. No external API calls, no network requests.

- `detect()` — < 1ms for typical messages
- `guard()` — < 1ms
- `redact()` — < 1ms
- Zero dependencies
- Works in Node.js, browsers, and edge runtimes

## License

MIT

## Contributing

Issues and pull requests are welcome at [github.com/keeperagent/crypto-key-guard](https://github.com/keeperagent/crypto-key-guard).
