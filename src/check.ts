import { KEY_PATTERNS } from "./patterns";
import { BIP39_WORDLIST } from "./wordlist";

/**
 * Check if a string looks like a crypto private key.
 *
 * Supports: Solana, EVM (Ethereum/BSC/Polygon/etc.), Aptos, Sui, Bitcoin WIF
 */
export const isPrivateKey = (value: string): boolean => {
  const trimmed = value.trim();

  for (const keyPattern of KEY_PATTERNS) {
    const pattern = new RegExp(`^${keyPattern.pattern.source}$`);
    if (pattern.test(trimmed)) {
      return true;
    }
  }

  return false;
};

/**
 * Check if a string looks like a BIP39 seed phrase (12 or 24 words).
 *
 * Works for all chains using BIP39: Bitcoin, Ethereum, Solana, Aptos, Sui, etc.
 */
export const isSeedPhrase = (value: string): boolean => {
  const words = value.trim().split(/\s+/);

  if (words.length !== 12 && words.length !== 24) {
    return false;
  }

  return words.every((word) => BIP39_WORDLIST.has(word.toLowerCase()));
};

/**
 * Check if a string contains any crypto secret (private key or seed phrase).
 */
export const containsSecret = (value: string): boolean => {
  return isPrivateKey(value) || isSeedPhrase(value);
};
