// Pure helpers for the Lint and Pyramid cards. No React so they can be unit-tested.

import type { LintCheck, LintResult } from "./types"

/** "2 errors · 1 warning · 10 checks passed", or "All 14 checks passed". */
export function summarizeLint(result: LintResult): string {
  const parts: string[] = []
  const n = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`
  if (result.counts.error) parts.push(n(result.counts.error, "error"))
  if (result.counts.warning) parts.push(n(result.counts.warning, "warning"))
  if (result.counts.info) parts.push(n(result.counts.info, "note"))
  if (parts.length === 0) return `All ${result.checks.length} checks passed`
  parts.push(`${result.passed} of ${result.checks.length} checks passed`)
  return parts.join(" · ")
}

/** Failed rows first, worst first, then passes in table order. */
export function orderChecks(checks: LintCheck[]): LintCheck[] {
  const rank: Record<LintCheck["status"], number> = { error: 0, warning: 1, info: 2, pass: 3 }
  return [...checks].sort((a, b) => rank[a.status] - rank[b.status] || checks.indexOf(a) - checks.indexOf(b))
}

export const TIER_STEPS: { tier: number; name: string; cost: string }[] = [
  { tier: 6, name: "TTPs", cost: "Change how the attack works" },
  { tier: 5, name: "Tools", cost: "Swap or rebuild the tool" },
  { tier: 4, name: "Host/network artifacts", cost: "Change paths, commands, keys" },
  { tier: 3, name: "Domain names", cost: "Register a new domain" },
  { tier: 2, name: "IP addresses", cost: "Rotate an address" },
  { tier: 1, name: "Hash values", cost: "Change one byte" },
]
