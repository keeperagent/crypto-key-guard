import { describe, it, expect } from "vitest";
import { detect } from "../src/detect";
import { isPrivateKey, isSeedPhrase } from "../src/check";
import { redact, restore, Rule } from "../src/redact";
import { guard } from "../src/guard";

// Example keys (NOT real keys — generated for testing only)
const SOLANA_PRIVATE_KEY =
  "4wBqpZM9msxygKxGzHYV5mGDrEULFnPGxFkQR3grRKAVchxbPFJNS9bSEHvPpPUFhEigmMbPB9SnCFDYEYPk6FaE";
const EVM_PRIVATE_KEY =
  "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3e5a1b0d5e8f2a5b1";
const BITCOIN_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const SEED_PHRASE_12 =
  "abandon ability able about above absent absorb abstract absurd abuse access accident";
const SEED_PHRASE_24 =
  "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual";

describe("detect", () => {
  it("should detect Solana private key", () => {
    const result = detect(`my key is ${SOLANA_PRIVATE_KEY}`);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("solana_private_key");
    expect(result[0].value).toBe(SOLANA_PRIVATE_KEY);
  });

  it("should detect EVM private key", () => {
    const result = detect(`use this key ${EVM_PRIVATE_KEY} for signing`);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("evm_private_key");
    expect(result[0].value).toBe(EVM_PRIVATE_KEY);
  });

  it("should detect Bitcoin WIF key", () => {
    const result = detect(`btc key: ${BITCOIN_WIF}`);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("bitcoin_wif");
    expect(result[0].value).toBe(BITCOIN_WIF);
  });

  it("should detect 12-word seed phrase", () => {
    const result = detect(`my seed phrase is ${SEED_PHRASE_12}`);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("seed_phrase_12");
  });

  it("should detect 24-word seed phrase", () => {
    const result = detect(`recovery phrase: ${SEED_PHRASE_24}`);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("seed_phrase_24");
  });

  it("should detect multiple secrets in one text", () => {
    const text = `solana key: ${SOLANA_PRIVATE_KEY} and eth key: ${EVM_PRIVATE_KEY}`;
    const result = detect(text);
    expect(result.length).toBeGreaterThanOrEqual(2);
  });

  it("should not detect normal text", () => {
    const result = detect("hello world, please swap 1 SOL to USDC");
    expect(result).toHaveLength(0);
  });

  it("should not detect short strings", () => {
    const result = detect("0x1234abcd");
    expect(result).toHaveLength(0);
  });

  it("should not detect normal words as seed phrase", () => {
    const result = detect(
      "I want to buy some tokens and sell them later for profit",
    );
    expect(result).toHaveLength(0);
  });
});

describe("isPrivateKey", () => {
  it("should identify Solana private key", () => {
    expect(isPrivateKey(SOLANA_PRIVATE_KEY)).toBe(true);
  });

  it("should identify EVM private key", () => {
    expect(isPrivateKey(EVM_PRIVATE_KEY)).toBe(true);
  });

  it("should identify Bitcoin WIF", () => {
    expect(isPrivateKey(BITCOIN_WIF)).toBe(true);
  });

  it("should reject normal text", () => {
    expect(isPrivateKey("hello world")).toBe(false);
  });

  it("should reject wallet address", () => {
    expect(isPrivateKey("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08")).toBe(
      false,
    );
  });
});

describe("isSeedPhrase", () => {
  it("should identify 12-word seed phrase", () => {
    expect(isSeedPhrase(SEED_PHRASE_12)).toBe(true);
  });

  it("should identify 24-word seed phrase", () => {
    expect(isSeedPhrase(SEED_PHRASE_24)).toBe(true);
  });

  it("should reject non-BIP39 words", () => {
    expect(
      isSeedPhrase(
        "foo bar baz qux quux corge grault garply waldo fred plugh xyzzy",
      ),
    ).toBe(false);
  });

  it("should reject wrong word count", () => {
    expect(isSeedPhrase("abandon ability able about above")).toBe(false);
  });
});

describe("redact", () => {
  it("should redact and restore EVM key", () => {
    const original = `use key ${EVM_PRIVATE_KEY} to sign`;
    const { text, secrets } = redact(original);

    expect(text).not.toContain(EVM_PRIVATE_KEY);
    expect(text).toContain("[EVM_KEY_1]");
    expect(secrets.get("[EVM_KEY_1]")).toBe(EVM_PRIVATE_KEY);

    const restored = restore(text, secrets);
    expect(restored).toBe(original);
  });

  it("should redact Solana key", () => {
    const { text } = redact(`key: ${SOLANA_PRIVATE_KEY}`);
    expect(text).not.toContain(SOLANA_PRIVATE_KEY);
    expect(text).toContain("[SOLANA_KEY_1]");
  });

  it("should return unchanged text when no secrets", () => {
    const original = "swap 1 SOL to USDC";
    const { text, secrets } = redact(original);
    expect(text).toBe(original);
    expect(secrets.size).toBe(0);
  });
});

describe("redact with additionalRules", () => {
  const openAiRule: Rule = {
    pattern: /sk-[a-zA-Z0-9]{48}/g,
    label: "OpenAI API Key",
    token: "OPENAI_KEY",
  };

  const bearerRule: Rule = {
    pattern: /Bearer [a-zA-Z0-9\-._~+/]+=*/g,
    label: "Bearer Token",
    token: "BEARER_TOKEN",
  };

  it("should redact a custom rule match", () => {
    const key = "sk-" + "a".repeat(48);
    const original = `call openai with ${key}`;
    const { text, secrets } = redact(original, { additionalRules: [openAiRule] });

    expect(text).not.toContain(key);
    expect(text).toContain("[OPENAI_KEY_1]");
    expect(secrets.get("[OPENAI_KEY_1]")).toBe(key);
  });

  it("should restore custom rule token back to original", () => {
    const key = "sk-" + "b".repeat(48);
    const original = `use key ${key} for request`;
    const { text, secrets } = redact(original, { additionalRules: [openAiRule] });
    const restored = restore(text, secrets);
    expect(restored).toBe(original);
  });

  it("should number multiple matches of the same custom rule", () => {
    const key1 = "sk-" + "a".repeat(48);
    const key2 = "sk-" + "b".repeat(48);
    const { text, secrets } = redact(`key1=${key1} key2=${key2}`, {
      additionalRules: [openAiRule],
    });

    expect(secrets.size).toBe(2);
    expect(text).toContain("[OPENAI_KEY_1]");
    expect(text).toContain("[OPENAI_KEY_2]");
  });

  it("should redact multiple different custom rules", () => {
    const apiKey = "sk-" + "c".repeat(48);
    const original = `key=${apiKey} auth=Bearer mytoken123`;
    const { text, secrets } = redact(original, {
      additionalRules: [openAiRule, bearerRule],
    });

    expect(text).not.toContain(apiKey);
    expect(text).not.toContain("Bearer mytoken123");
    expect(secrets.size).toBe(2);
  });

  it("should redact both built-in crypto keys and custom rules together", () => {
    const apiKey = "sk-" + "d".repeat(48);
    const original = `openai=${apiKey} eth=${EVM_PRIVATE_KEY}`;
    const { text, secrets } = redact(original, { additionalRules: [openAiRule] });

    expect(text).not.toContain(apiKey);
    expect(text).not.toContain(EVM_PRIVATE_KEY);
    expect(secrets.size).toBe(2);
    expect(text).toContain("[OPENAI_KEY_1]");
    expect(text).toContain("[EVM_KEY_1]");
  });

  it("should not redact when custom rule does not match", () => {
    const original = "no secrets here";
    const { text, secrets } = redact(original, { additionalRules: [openAiRule] });
    expect(text).toBe(original);
    expect(secrets.size).toBe(0);
  });
});

describe("guard", () => {
  it("should block text with private key", () => {
    const result = guard(`here is my key ${EVM_PRIVATE_KEY}`);
    expect(result.detected).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.message).toContain("Blocked");
  });

  it("should block text with seed phrase", () => {
    const result = guard(SEED_PHRASE_12);
    expect(result.detected).toBe(true);
    expect(result.message).toContain("seed");
  });

  it("should allow safe text", () => {
    const result = guard("check my SOL balance");
    expect(result.detected).toBe(false);
    expect(result.message).toBe("");
  });
});
