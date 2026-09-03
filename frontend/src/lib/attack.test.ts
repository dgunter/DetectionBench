import { describe, expect, it } from "vitest"
import { summarizeAttack, type AttackMapping } from "./attack"

const base: AttackMapping = {
  dataset_version: "19.2",
  techniques: [],
  tactics: [],
  unvalidated: [],
  other_tags: [],
  findings: [],
  provenance: "deterministic:metadata",
  confidence: "high",
  declared_count: 0,
}

describe("summarizeAttack", () => {
  it("handles the empty case", () => {
    expect(summarizeAttack(base)).toBe("No ATT&CK tags declared")
  })
  it("pluralizes and counts only non-info findings as issues", () => {
    const m: AttackMapping = {
      ...base,
      techniques: [{} as never, {} as never],
      tactics: [{} as never],
      unvalidated: ["attack.s0002"],
      findings: [
        { check: "a", severity: "info", message: "", tag: null, confidence: "high" },
        { check: "b", severity: "error", message: "", tag: null, confidence: "high" },
      ],
    }
    expect(summarizeAttack(m)).toBe("2 techniques · 1 tactic · 1 unvalidated tag · 1 issue")
  })
})
