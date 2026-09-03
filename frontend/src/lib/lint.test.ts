import { describe, expect, it } from "vitest"
import { orderChecks, summarizeLint } from "./lint"
import type { LintCheck, LintResult } from "./types"

const check = (check: string, status: LintCheck["status"]): LintCheck => ({ check, label: check, status, message: null })

const base: LintResult = {
  value: "",
  checks: [check("title", "pass"), check("id", "error"), check("status", "warning"), check("attack", "info")],
  findings: [],
  counts: { error: 1, warning: 1, info: 1 },
  passed: 1,
  provenance: "deterministic:metadata",
  confidence: "high",
  rationale: "",
}

describe("summarizeLint", () => {
  it("lists counts then the pass ratio", () => {
    expect(summarizeLint(base)).toBe("1 error · 1 warning · 1 note · 1 of 4 checks passed")
  })
  it("says all passed when clean", () => {
    const clean = { ...base, checks: base.checks.map((c) => ({ ...c, status: "pass" as const })), counts: { error: 0, warning: 0, info: 0 }, passed: 4 }
    expect(summarizeLint(clean)).toBe("All 4 checks passed")
  })
})

describe("orderChecks", () => {
  it("puts failures first, worst first, passes last in table order", () => {
    expect(orderChecks(base.checks).map((c) => c.check)).toEqual(["id", "status", "attack", "title"])
  })
})
