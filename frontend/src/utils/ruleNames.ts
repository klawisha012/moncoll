// Map an OWASP CRS rule ID (e.g. "941100") to a human-readable injection name
// (e.g. "XSS"). Used by Tests and Dashboard so the UI never shows a bare rule
// number — the family prefix carries the meaning. Unknown prefixes fall back
// to the raw rule id.

const FAMILY_BY_PREFIX: Record<string, string> = {
  "911": "Method",
  "913": "Scanner",
  "920": "Protocol Enforcement",
  "921": "Protocol Attack",
  "922": "Multipart",
  "930": "LFI",
  "931": "RFI",
  "932": "RCE",
  "933": "PHP Injection",
  "934": "Generic Attack",
  "941": "XSS",
  "942": "SQL Injection",
  "943": "Session Fixation",
  "944": "Java Injection",
  "949": "Blocking Eval",
};

export function injectionName(ruleId: string | null | undefined): string {
  if (!ruleId) return "—";
  const prefix = ruleId.slice(0, 3);
  return FAMILY_BY_PREFIX[prefix] ?? ruleId;
}

// "XSS · 941100" — name primary, rule id secondary on the same line.
// Falls back to the raw rule id when the family is unknown.
export function injectionLabel(ruleId: string | null | undefined): string {
  if (!ruleId) return "—";
  const name = injectionName(ruleId);
  return name === ruleId ? ruleId : `${name} · ${ruleId}`;
}

// Map a ModSecurity rule **file** (e.g. "REQUEST-941-APPLICATION-ATTACK-XSS",
// already stripped of path + .conf by the backend) to its injection family
// name. Falls back to the original file string if the prefix is unknown.
export function ruleFileToFamily(file: string | null | undefined): string {
  if (!file) return "—";
  const match = file.match(/^REQUEST-(\d{3})-/i);
  if (!match) return file;
  return FAMILY_BY_PREFIX[match[1]] ?? file;
}
