import { describe, expect, it } from "vitest"
import { countCriteria, criterionLabel, flattenAst, provenanceLabel } from "./ast"
import type { AstNode, CriterionNode } from "./types"

const crit = (field: string | null, modifiers: string[] = [], selection = "selection"): CriterionNode => ({
  kind: "criterion",
  selection,
  field,
  modifiers,
  values: ["v"],
  value_type: "string",
  tier: 4,
  tier_name: "Host/network artifacts",
  category: "host_artifact",
  confidence: "high",
  note: null,
  routing: false,
  outcome: false,
})

const tree: AstNode = {
  kind: "boolean",
  op: "and",
  selection: null,
  children: [
    { kind: "boolean", op: "or", selection: "selection", children: [crit("CommandLine", ["contains"]), crit("Image", ["contains"])] },
    { kind: "boolean", op: "not", selection: null, children: [crit("Image", ["endswith"], "filter_main")] },
  ],
}

describe("flattenAst", () => {
  it("walks depth-first with depths and selection names", () => {
    const lines = flattenAst(tree)
    expect(lines.map((l) => [l.depth, l.label, l.selection])).toEqual([
      [0, "AND", null],
      [1, "OR", "selection"],
      [2, "CommandLine|contains", "selection"],
      [2, "Image|contains", "selection"],
      [1, "NOT", null],
      [2, "Image|endswith", "filter_main"],
    ])
  })
  it("counts leaves", () => {
    expect(countCriteria(tree)).toBe(3)
  })
})

describe("criterionLabel", () => {
  it("uses Sigma's pipe spelling and names keyword searches", () => {
    expect(criterionLabel(crit("CommandLine", ["contains", "all"]))).toBe("CommandLine|contains|all")
    expect(criterionLabel(crit(null))).toBe("keyword")
  })
})

describe("provenanceLabel", () => {
  it("renders the three provenance kinds", () => {
    expect(provenanceLabel("deterministic:ast")).toBe("Deterministic · AST")
    expect(provenanceLabel("inferred:llm")).toBe("Inferred · LLM")
  })
})
