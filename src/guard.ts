import { detect, Finding } from "./detect";

export type GuardResult = {
  /** Whether any secrets were detected */
  detected: boolean;
  /** All findings */
  findings: Finding[];
  /** Human-readable warning message */
  message: string;
};

/**
 * Check text for crypto secrets and return a warning if found.
 * Use this to block messages containing private keys or seed phrases
 * before they are sent to an LLM provider.
 *
 * @example
 * ```ts
 * const result = guard(userMessage);
 * if (result.detected) {
 *   // Block the message, show warning to user
 *   console.warn(result.message);
 *   return; // do NOT send to LLM
 * }
 * // Safe to send to LLM
 * ```
 */
export const guard = (text: string): GuardResult => {
  const findings = detect(text);

  if (findings.length === 0) {
    return {
      detected: false,
      findings: [],
      message: "",
    };
  }

  const types = [...new Set(findings.map((finding) => finding.label))];
  const message =
    `Blocked: detected ${findings.length} crypto secret(s) in text: ${types.join(", ")}. ` +
    `This message was NOT sent to the AI provider. Never share your private keys or seed phrases.`;

  return {
    detected: true,
    findings,
    message,
  };
};
