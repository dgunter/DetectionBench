import { describe, expect, it } from "vitest"
import { describeDelta, describeLlmError, type CandidateResult } from "./llm"

const base: CandidateResult = {
  index: 0,
  strategy: "s",
  yaml: "title: x",
  verdict: "preserved",
  label: "Tier preserved",
  is_win: true,
  score: { ok: true, tier: 4, tier_name: "Artifact", confidence: "high", lint_errors: 0, lint_warnings: 1, parse_error: null },
  tier_delta: 0,
  lint_error_delta: -1,
  lint_warning_delta: 0,
}

describe("describeDelta", () => {
  it("formats tier and lint deltas with signs", () => {
    expect(describeDelta(base)).toBe("tier same · lint errors -1")
    expect(describeDelta({ ...base, verdict: "raised", tier_delta: 2, lint_error_delta: 0 })).toBe("tier +2")
    expect(describeDelta({ ...base, verdict: "parse_failed" })).toBe("not scored")
  })
})

describe("describeLlmError", () => {
  it("prefers the server message, then falls back by status", () => {
    expect(describeLlmError(503, "overloaded", "busy")).toBe("busy")
    expect(describeLlmError(429, "budget_exhausted", undefined)).toMatch(/budget/)
    expect(describeLlmError(504, undefined, undefined)).toMatch(/too long/)
    expect(describeLlmError(500, undefined, undefined)).toBe("The AI request failed.")
  })
})
