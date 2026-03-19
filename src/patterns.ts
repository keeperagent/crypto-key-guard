export type SecretType =
  | "solana_private_key"
  | "evm_private_key"
  | "bitcoin_wif"
  | "seed_phrase_12"
  | "seed_phrase_24";

export type SecretPattern = {
  type: SecretType;
  label: string;
  pattern: RegExp;
};

// Solana private key: base58 encoded, 87-88 characters
// Uses ed25519, encoded as base58 (no 0, O, I, l characters)
const SOLANA_PRIVATE_KEY: SecretPattern = {
  type: "solana_private_key",
  label: "Solana Private Key",
  pattern: /\b[1-9A-HJ-NP-Za-km-z]{87,88}\b/g,
};

// EVM private key (Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, etc.)
// Also matches Aptos and Sui private keys (same format: 0x + 64 hex chars)
// Must be exactly 0x + 64 hex characters
const EVM_PRIVATE_KEY: SecretPattern = {
  type: "evm_private_key",
  label: "EVM/Aptos/Sui Private Key",
  pattern: /\b0x[a-fA-F0-9]{64}\b/g,
};

// Bitcoin WIF (Wallet Import Format)
// Mainnet: starts with 5 (uncompressed) or K/L (compressed)
// Length: 51 (uncompressed) or 52 (compressed) base58 characters
const BITCOIN_WIF: SecretPattern = {
  type: "bitcoin_wif",
  label: "Bitcoin WIF Private Key",
  pattern: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g,
};

export const KEY_PATTERNS: SecretPattern[] = [
  SOLANA_PRIVATE_KEY,
  EVM_PRIVATE_KEY,
  BITCOIN_WIF,
];
