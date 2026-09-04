// Inline tooltip copy for the five cards and the panel controls.
// Source of truth for the longer form is the "How this works" page.

export const TOOLTIPS = {
  structure: "The rule's logic broken into its structural pieces — the intermediate representation (IR) produced by static analysis of the rule.",
  scope: "Plain-language read of what this rule actually matches, derived from the same parsed logic.",
  pyramid: "How durable this detection is — see 'How this works' for the full framework.",
  lint: "Metadata completeness check — separate from whether the detection logic itself is strong.",
  attack: "Declared technique IDs, checked against a real offline copy of MITRE ATT&CK.",
  confidence: "How sure we are, and whether this came from parsing the rule, reading its metadata, or an AI guess.",
  modelSelector: "Pick which Claude model answers — the deterministic cards above don't change no matter which you choose.",
} as const

export const PROVENANCE_LABELS: Record<string, string> = {
  "deterministic:static": "Deterministic · static analysis",
  "deterministic:metadata": "Deterministic · metadata",
  "inferred:llm": "Inferred · LLM",
}
