import { KEY_PATTERNS, SecretType } from "./patterns";
import { BIP39_WORDLIST } from "./wordlist";

export type Finding = {
  type: SecretType;
  label: string;
  value: string;
  start: number;
  end: number;
};

const isSeedPhrase = (words: string[]): boolean => {
  return words.every((word) => BIP39_WORDLIST.has(word.toLowerCase()));
};

const detectSeedPhrases = (text: string): Finding[] => {
  const findings: Finding[] = [];
  const words = text.split(/\s+/);

  // Try to find sequences of 24 or 12 consecutive BIP39 words
  for (const targetLength of [24, 12]) {
    if (words.length < targetLength) {
      continue;
    }

    for (
      let startIndex = 0;
      startIndex <= words.length - targetLength;
      startIndex++
    ) {
      const candidate = words.slice(startIndex, startIndex + targetLength);

      if (isSeedPhrase(candidate)) {
        const phrase = candidate.join(" ");
        const beforeWords = words.slice(0, startIndex).join(" ");
        const start = beforeWords.length > 0 ? beforeWords.length + 1 : 0;

        // Check this range isn't already covered by a longer finding
        const alreadyCovered = findings.some(
          (finding) =>
            start >= finding.start && start + phrase.length <= finding.end,
        );
        if (alreadyCovered) {
          continue;
        }

        findings.push({
          type: targetLength === 12 ? "seed_phrase_12" : "seed_phrase_24",
          label: `BIP39 Seed Phrase (${targetLength} words)`,
          value: phrase,
          start,
          end: start + phrase.length,
        });
      }
    }
  }

  return findings;
};

const detectKeys = (text: string): Finding[] => {
  const findings: Finding[] = [];

  for (const keyPattern of KEY_PATTERNS) {
    // Reset regex state
    const pattern = new RegExp(
      keyPattern.pattern.source,
      keyPattern.pattern.flags,
    );
    let match;

    while ((match = pattern.exec(text)) !== null) {
      findings.push({
        type: keyPattern.type,
        label: keyPattern.label,
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  return findings;
};

/**
 * Detect crypto private keys and seed phrases in text.
 *
 * Supports:
 * - Solana private keys (base58, 87-88 chars)
 * - EVM private keys (0x + 64 hex chars) — Ethereum, BSC, Polygon, Arbitrum, etc.
 * - Aptos/Sui private keys (0x + 64 hex chars)
 * - Bitcoin WIF private keys
 * - BIP39 seed phrases (12 or 24 words)
 */
export const detect = (text: string): Finding[] => {
  const keyFindings = detectKeys(text);
  const seedFindings = detectSeedPhrases(text);
  const allFindings = [...keyFindings, ...seedFindings];

  // Sort by position in text
  allFindings.sort((a, b) => a.start - b.start);

  return allFindings;
};
