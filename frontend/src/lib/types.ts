// Shapes returned by POST /api/classify. Mirrors backend/app/pipeline/*.to_dict().

import type { AttackMapping } from "./attack"

export type Confidence = "high" | "medium" | "low"
export type Provenance = "deterministic:static" | "deterministic:metadata" | "inferred:llm"

export interface CriterionNode {
  kind: "criterion"
  selection: string
  field: string | null
  modifiers: string[]
  values: string[]
  value_type: string
  tier: number
  tier_name: string
  category: string
  confidence: Confidence
  note: string | null
  routing: boolean
  outcome: boolean
}

export interface BooleanNode {
  kind: "boolean"
  op: "and" | "or" | "not"
  selection: string | null
  children: StructureNode[]
}

export type StructureNode = CriterionNode | BooleanNode

export interface RuleMetadata {
  title: string | null
  id: string | null
  status: string | null
  level: string | null
  description: string | null
  author: string | null
  date: string | null
  modified: string | null
  references: string[]
  falsepositives: string[]
  tags: string[]
  logsource: { category: string | null; product: string | null; service: string | null }
}

export interface StructureResult {
  value: string
  confidence: Confidence
  provenance: Provenance
  rationale: string
  condition: string
  selections: string[]
  root: StructureNode
  metadata: RuleMetadata
  metadata_errors: { type: string; message: string }[]
}

export interface OutlineLine {
  depth: number
  text: string
  role: "criterion" | "and" | "or" | "not" | "filter"
  selection: string | null
}

export interface ScopeResult {
  value: string
  summary: string
  logsource_text: string
  outline: OutlineLine[]
  fields: string[]
  selections: { name: string; role: "primary" | "filter"; criteria: number }[]
  criteria_count: number
  filter_count: number
  provenance: Provenance
  confidence: Confidence
  rationale: string
}

export interface Advisory {
  kind: "filter" | "routing" | "bare_not" | "level_vs_tier"
  message: string
  detail: Record<string, unknown>
}

export interface PyramidResult {
  value: string
  tier: number
  tier_name: string
  confidence: Confidence
  provenance: Provenance
  rationale: string
  steps: string[]
  categories: string[]
  advisories: Advisory[]
}

export interface LintFinding {
  check: string
  severity: "error" | "warning" | "info"
  message: string
  tag: string | null
  confidence: string
}

export interface LintCheck {
  check: string
  label: string
  status: "pass" | "error" | "warning" | "info"
  message: string | null
}

export interface LintResult {
  value: string
  checks: LintCheck[]
  findings: LintFinding[]
  counts: { error: number; warning: number; info: number }
  passed: number
  provenance: Provenance
  confidence: Confidence
  rationale: string
}

export interface ParseFailure {
  code: string
  message: string
  detail: string | null
}

export interface ClassifyResponse {
  ok: boolean
  error: ParseFailure | null
  structure: StructureResult | null
  scope: ScopeResult | null
  pyramid: PyramidResult | null
  lint: LintResult | null
  attack: AttackMapping | null
}
