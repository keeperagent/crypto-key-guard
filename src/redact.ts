import { detect, Finding } from "./detect";

export type RedactResult = {
  /** Text with secrets replaced by tokens */
  text: string;
  /** Map of token → original secret value */
  secrets: Map<string, string>;
  /** All findings detected */
  findings: Finding[];
};

const TOKEN_PREFIXES: Record<string, string> = {
  solana_private_key: "SOLANA_KEY",
  evm_private_key: "EVM_KEY",
  bitcoin_wif: "BTC_KEY",
  seed_phrase_12: "SEED_PHRASE",
  seed_phrase_24: "SEED_PHRASE",
};

/**
 * Detect and replace crypto secrets with safe tokens.
 * Returns the redacted text and a map to restore original values.
 *
 * @example
 * ```ts
 * const { text, secrets } = redact("my key is 0x1a2b3c...");
 * // text: "my key is [EVM_KEY_1]"
 * // secrets: Map { "[EVM_KEY_1]" => "0x1a2b3c..." }
 * ```
 */
export const redact = (text: string): RedactResult => {
  const findings = detect(text);

  if (findings.length === 0) {
    return { text, secrets: new Map(), findings };
  }

  const secrets = new Map<string, string>();
  const counters = new Map<string, number>();
  let result = text;

  // Process findings from end to start to preserve indices
  const reversed = [...findings].sort((a, b) => b.start - a.start);

  for (const finding of reversed) {
    const prefix = TOKEN_PREFIXES[finding.type] || "SECRET";
    const count = (counters.get(prefix) || 0) + 1;
    counters.set(prefix, count);
    const token = `[${prefix}_${count}]`;

    secrets.set(token, finding.value);
    result = result.slice(0, finding.start) + token + result.slice(finding.end);
  }

  return { text: result, secrets, findings };
};

/**
 * Restore redacted tokens back to original values.
 *
 * @example
 * ```ts
 * const { text, secrets } = redact("my key is 0x1a2b3c...");
 * const restored = restore(text, secrets);
 * // restored: "my key is 0x1a2b3c..."
 * ```
 */
export const restore = (text: string, secrets: Map<string, string>): string => {
  let result = text;

  for (const [token, value] of secrets) {
    result = result.replace(token, value);
  }

  return result;
};
