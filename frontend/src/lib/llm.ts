// Types and pure helpers for the AI panel. Mirrors backend app/api/llm.py envelopes.

export type ModelKey = "opus" | "sonnet" | "fable"
export type LlmAction = "explain" | "suggest_attack" | "candidates"

export interface LlmEnvelope {
  action: LlmAction
  model: ModelKey
  provenance: "inferred:llm"
  confidence: "low"
}

export interface ExplainResult extends LlmEnvelope {
  action: "explain"
  text: string
}

export interface AttackSuggestion {
  id: string
  name: string
  url: string | null
  status: "valid" | "retired" | "unknown"
  replaced_by: string | null
  rationale: string
  confidence: "high" | "medium" | "low"
  already_declared: boolean
}

export interface SuggestAttackResult extends LlmEnvelope {
  action: "suggest_attack"
  suggestions: AttackSuggestion[]
  dataset_version: string
}

export interface ScoreSummary {
  ok: boolean
  tier: number | null
  tier_name: string | null
  confidence: string | null
  lint_errors: number | null
  lint_warnings: number | null
  parse_error: string | null
}

export type CandidateVerdict = "raised" | "preserved" | "regressed" | "parse_failed"

export interface CandidateResult {
  index: number
  strategy: string
  yaml: string
  verdict: CandidateVerdict
  label: string
  is_win: boolean
  score: ScoreSummary
  tier_delta: number | null
  lint_error_delta: number | null
  lint_warning_delta: number | null
}

export interface CandidatesResult extends LlmEnvelope {
  action: "candidates"
  original: ScoreSummary
  candidates: CandidateResult[]
}

export interface LlmErrorBody {
  code: string
  message: string
}

/** Friendly copy for a failed panel action. Server messages are already user-safe; fall back by status. */
export function describeLlmError(status: number, code: string | undefined, message: string | undefined): string {
  if (message) return message
  switch (status) {
    case 429:
      return code === "budget_exhausted" ? "The shared hourly AI budget is used up." : "Too many AI requests. Wait a minute."
    case 503:
      return "The model is unavailable right now. Try again shortly."
    case 504:
      return "The model took too long to answer. Try again."
    case 401:
      return "Your session expired. Sign in again."
    default:
      return "The AI request failed."
  }
}

/** Short delta text for a candidate card, e.g. "tier +2 · lint errors −1". */
export function describeDelta(c: CandidateResult): string {
  if (c.verdict === "parse_failed") return "not scored"
  const parts: string[] = []
  const signed = (n: number) => (n > 0 ? `+${n}` : `${n}`)
  parts.push(c.tier_delta === null ? "tier n/a" : c.tier_delta === 0 ? "tier same" : `tier ${signed(c.tier_delta)}`)
  if (c.lint_error_delta !== null && c.lint_error_delta !== 0) parts.push(`lint errors ${signed(c.lint_error_delta)}`)
  if (c.lint_warning_delta !== null && c.lint_warning_delta !== 0) parts.push(`lint warnings ${signed(c.lint_warning_delta)}`)
  return parts.join(" · ")
}
