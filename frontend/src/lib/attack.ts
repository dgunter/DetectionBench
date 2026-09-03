// Mirrors backend `app/pipeline/attack_map.py` AttackMapping.to_dict().

export type Severity = "error" | "warning" | "info"

export interface AttackFinding {
  check: string
  severity: Severity
  message: string
  tag: string | null
  confidence: string
}

export interface TechniqueRef {
  tag: string
  id: string
  status: "valid" | "retired" | "unknown"
  name: string | null
  url: string | null
  tactics: string[]
  is_subtechnique: boolean
  replaced_by: string | null
  replaced_by_name: string | null
}

export interface TacticRef {
  tag: string
  name: string
  status: "valid" | "renamed" | "unknown"
  renamed_to: string | null
}

export interface AttackMapping {
  dataset_version: string
  techniques: TechniqueRef[]
  tactics: TacticRef[]
  unvalidated: string[]
  other_tags: string[]
  findings: AttackFinding[]
  provenance: string
  confidence: string
  declared_count: number
}

/** One-line summary for the card header, e.g. "2 techniques · 1 tactic · 1 issue". */
export function summarizeAttack(m: AttackMapping): string {
  const parts: string[] = []
  const n = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`
  if (m.techniques.length) parts.push(n(m.techniques.length, "technique"))
  if (m.tactics.length) parts.push(n(m.tactics.length, "tactic"))
  if (m.unvalidated.length) parts.push(n(m.unvalidated.length, "unvalidated tag"))
  const issues = m.findings.filter((f) => f.severity !== "info").length
  if (issues) parts.push(n(issues, "issue"))
  return parts.length ? parts.join(" · ") : "No ATT&CK tags declared"
}
