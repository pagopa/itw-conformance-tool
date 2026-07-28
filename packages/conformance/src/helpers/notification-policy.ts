export type UserNeutralEventDescriptionReasonCode =
  'device-state-disclosure' | 'personal-identifier-disclosure' | 'user-behavior-disclosure';

export interface UserNeutralEventDescriptionResult {
  neutral: boolean;
  reasonCodes: UserNeutralEventDescriptionReasonCode[];
}

// Conservative, non-exhaustive lexical indicators of Device state/capability
// disclosure. A regex cannot prove semantic neutrality for every language or
// phrasing (see WP_064b), so this only intercepts explicit, unambiguous
// disclosures and treats everything else as user-neutral.
const DEVICE_STATE_PATTERNS = [
  /\bstorage\b/i,
  /\bout of (space|memory)\b/i,
  /\bdisk\s*(space|full)\b/i,
  /\bbattery\b/i,
  /\boffline\b/i,
  /\bwi-?fi\b/i,
  /\bnetwork connection\b/i,
  /\bsignal strength\b/i,
  /\bfirmware\b/i,
  /\boperating system\b/i
];

const USER_BEHAVIOR_PATTERNS = [
  /\buser (declined|refused|cancell?ed|ignored|tapped|clicked|confirmed|accepted)\b/i,
  /\b(declined|refused|cancell?ed) (the|this) (request|notification|operation)\b/i,
  /\buser'?s (consent|decision|behavio(u)?r|choice)\b/i,
  /\bdevice owner\b/i
];

const PERSONAL_IDENTIFIER_PATTERNS = [
  /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/, // email address
  /\+?\d[\d\s-]{7,}\d/, // phone-like sequences
  /\bcodice fiscale\b/i,
  /\bfiscal code\b/i,
  /\bssn\b/i
];

/**
 * Conservative, lexical WP_064b conformance policy: rejects `event_description`
 * values that contain explicit device-state/capability, user-behavior, or
 * personal identifier disclosures, and treats everything else as
 * user-neutral. This is a heuristic, not a semantic proof: it cannot
 * guarantee neutrality for every possible language or phrasing, only
 * intercept unambiguous disclosures.
 *
 * This is conformance-testing evaluation logic (WP_064b), not a System Under
 * Test protocol validation rule; it lives in the conformance package so that
 * `apps/itw-credential-issuer` only calls into it to produce diagnostic
 * evidence and never owns the testing heuristic itself.
 */
export function evaluateUserNeutralEventDescription(value: string): UserNeutralEventDescriptionResult {
  const reasonCodes: UserNeutralEventDescriptionReasonCode[] = [];

  if (DEVICE_STATE_PATTERNS.some((pattern) => pattern.test(value))) {
    reasonCodes.push('device-state-disclosure');
  }
  if (USER_BEHAVIOR_PATTERNS.some((pattern) => pattern.test(value))) {
    reasonCodes.push('user-behavior-disclosure');
  }
  if (PERSONAL_IDENTIFIER_PATTERNS.some((pattern) => pattern.test(value))) {
    reasonCodes.push('personal-identifier-disclosure');
  }

  return { neutral: reasonCodes.length === 0, reasonCodes };
}
