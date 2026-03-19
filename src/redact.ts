import { detect, Finding } from "./detect";

export type RedactResult = {
  /** Text with secrets replaced by tokens */
  text: string;
  /** Map of token → original secret value */
  secrets: Map<string, string>;
  /** Built-in crypto findings detected */
  findings: Finding[];
};

/**
 * A custom rule for redacting additional secrets beyond built-in crypto keys.
 *
 * @example
 * ```ts
 * const openAiRule: Rule = {
 *   pattern: /sk-[a-zA-Z0-9]{48}/g,
 *   label: "OpenAI API Key",
 *   token: "OPENAI_KEY", // replaced as [OPENAI_KEY_1], [OPENAI_KEY_2], ...
 * };
 * const { text, secrets } = redact(input, { additionalRules: [openAiRule] });
 * ```
 */
export type Rule = {
  /** RegExp to match the secret. Must include the `g` flag. */
  pattern: RegExp;
  /** Human-readable label describing the secret type */
  label: string;
  /** Token prefix used in replacement, e.g. "OPENAI_KEY" → [OPENAI_KEY_1] */
  token: string;
};

export type RedactOptions = {
  /** Additional rules to detect and redact beyond built-in crypto keys */
  additionalRules?: Rule[];
};

const TOKEN_PREFIXES: Record<string, string> = {
  solana_private_key: "SOLANA_KEY",
  evm_private_key: "EVM_KEY",
  bitcoin_wif: "BTC_KEY",
  seed_phrase_12: "SEED_PHRASE",
  seed_phrase_24: "SEED_PHRASE",
};

type WorkingFinding = {
  token: string;
  value: string;
  start: number;
  end: number;
};

/**
 * Detect and replace crypto secrets (and optional custom rules) with safe tokens.
 * Returns the redacted text and a map to restore original values.
 *
 * @example
 * ```ts
 * // Built-in crypto detection
 * const { text, secrets } = redact("my key is 0x1a2b3c...");
 * // text: "my key is [EVM_KEY_1]"
 * // secrets: Map { "[EVM_KEY_1]" => "0x1a2b3c..." }
 *
 * // With custom rules
 * const { text, secrets } = redact(input, {
 *   additionalRules: [
 *     { pattern: /sk-[a-zA-Z0-9]{48}/g, label: "OpenAI API Key", token: "OPENAI_KEY" },
 *   ],
 * });
 * ```
 */
export const redact = (text: string, options?: RedactOptions): RedactResult => {
  const findings = detect(text);

  // Convert built-in findings to working findings
  const workingFindings: WorkingFinding[] = findings.map((f) => ({
    token: TOKEN_PREFIXES[f.type] || "SECRET",
    value: f.value,
    start: f.start,
    end: f.end,
  }));

  // Collect custom rule matches
  if (options?.additionalRules) {
    for (const rule of options.additionalRules) {
      const pattern = new RegExp(
        rule.pattern.source,
        rule.pattern.flags.includes("g")
          ? rule.pattern.flags
          : rule.pattern.flags + "g",
      );
      let match;
      while ((match = pattern.exec(text)) !== null) {
        workingFindings.push({
          token: rule.token,
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
        });
      }
    }
  }

  if (workingFindings.length === 0) {
    return { text, secrets: new Map(), findings };
  }

  // Sort by position, then remove overlaps keeping the first match
  const sorted = [...workingFindings].sort((a, b) => a.start - b.start);
  const deduped: WorkingFinding[] = [];
  for (const finding of sorted) {
    const overlaps = deduped.some(
      (kept) => finding.start < kept.end && finding.end > kept.start,
    );
    if (!overlaps) deduped.push(finding);
  }

  // Assign token numbers in reading order (left to right)
  const secrets = new Map<string, string>();
  const counters = new Map<string, number>();
  const assigned: { finding: WorkingFinding; token: string; }[] = [];
  for (const finding of deduped) {
    const count = (counters.get(finding.token) || 0) + 1;
    counters.set(finding.token, count);
    assigned.push({ finding, token: `[${finding.token}_${count}]` });
  }

  // Apply replacements from end to start to preserve indices
  let result = text;
  for (const { finding, token } of [...assigned].reverse()) {
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
