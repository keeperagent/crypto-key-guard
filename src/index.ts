export { detect } from "./detect";
export type { Finding } from "./detect";

export { redact, restore } from "./redact";
export type { RedactResult } from "./redact";

export { guard } from "./guard";
export type { GuardResult } from "./guard";

export { isPrivateKey, isSeedPhrase, containsSecret } from "./check";

export type { SecretType, SecretPattern } from "./patterns";
export { KEY_PATTERNS } from "./patterns";
export { BIP39_WORDLIST } from "./wordlist";
