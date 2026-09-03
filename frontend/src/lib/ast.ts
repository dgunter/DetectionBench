// Pure helpers for rendering the parsed condition tree. No React here so they can be unit-tested.

import type { AstNode, Confidence, CriterionNode } from "./types"

export interface AstLine {
  depth: number
  kind: "boolean" | "criterion"
  label: string
  selection: string | null
  criterion?: CriterionNode
}

const OP_LABEL: Record<"and" | "or" | "not", string> = { and: "AND", or: "OR", not: "NOT" }

/** Flatten the tree depth-first into renderable lines. */
export function flattenAst(node: AstNode, depth = 0, out: AstLine[] = []): AstLine[] {
  if (node.kind === "criterion") {
    out.push({ depth, kind: "criterion", label: criterionLabel(node), selection: node.selection, criterion: node })
    return out
  }
  out.push({ depth, kind: "boolean", label: OP_LABEL[node.op], selection: node.selection })
  for (const child of node.children) flattenAst(child, depth + 1, out)
  return out
}

/** `Field|mod1|mod2` in Sigma's own spelling, or `keyword` for field-less searches. */
export function criterionLabel(c: CriterionNode): string {
  if (c.field === null) return "keyword"
  return [c.field, ...c.modifiers].join("|")
}

export function countCriteria(node: AstNode): number {
  return node.kind === "criterion" ? 1 : node.children.reduce((n, c) => n + countCriteria(c), 0)
}

/** Tailwind classes for the six Pyramid of Pain tiers, low (cheap to evade) to high. */
export function tierTone(tier: number): string {
  switch (tier) {
    case 1:
      return "bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-200"
    case 2:
      return "bg-orange-100 text-orange-900 dark:bg-orange-950 dark:text-orange-200"
    case 3:
      return "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200"
    case 4:
      return "bg-lime-100 text-lime-900 dark:bg-lime-950 dark:text-lime-200"
    case 5:
      return "bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200"
    case 6:
      return "bg-teal-100 text-teal-900 dark:bg-teal-950 dark:text-teal-200"
    default:
      return "bg-muted text-muted-foreground"
  }
}

export function confidenceTone(confidence: Confidence): string {
  if (confidence === "high") return "border-emerald-300 text-emerald-800 dark:text-emerald-300"
  if (confidence === "medium") return "border-amber-300 text-amber-800 dark:text-amber-300"
  return "border-red-300 text-red-800 dark:text-red-300"
}

export function provenanceLabel(provenance: string): string {
  switch (provenance) {
    case "deterministic:ast":
      return "Deterministic · AST"
    case "deterministic:metadata":
      return "Deterministic · metadata"
    case "inferred:llm":
      return "Inferred · LLM"
    default:
      return provenance
  }
}
