import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { CARD_TOOLTIPS, ConfidenceBadge, ResultCard, type CardState } from "@/components/ResultCard"
import { orderChecks, summarizeLint } from "@/lib/lint"
import { cn } from "@/lib/utils"
import type { LintCheck, LintResult } from "@/lib/types"

const STATUS_ICON: Record<LintCheck["status"], { icon: typeof CheckCircle2; tone: string }> = {
  pass: { icon: CheckCircle2, tone: "text-emerald-600 dark:text-emerald-400" },
  error: { icon: XCircle, tone: "text-red-600 dark:text-red-400" },
  warning: { icon: AlertTriangle, tone: "text-amber-600 dark:text-amber-400" },
  info: { icon: Info, tone: "text-sky-600 dark:text-sky-400" },
}

export function LintCard({ state, lint }: Readonly<{ state: CardState; lint: LintResult | null }>) {
  return (
    <ResultCard
      title="Lint results"
      tooltip={CARD_TOOLTIPS.lint}
      state={state}
      badge={lint && state === "ready" ? <ConfidenceBadge confidence={lint.confidence} provenance={lint.provenance} /> : undefined}
    >
      {lint && (
        <div className="space-y-2">
          <p className="flex flex-wrap items-center gap-1.5">
            <span>{summarizeLint(lint)}</span>
            {lint.counts.error > 0 && <Badge variant="destructive">{lint.counts.error} error{lint.counts.error === 1 ? "" : "s"}</Badge>}
          </p>
          <ul className="space-y-1 text-xs" aria-label="Lint checks">
            {orderChecks(lint.checks).map((c) => {
              const { icon: Icon, tone } = STATUS_ICON[c.status]
              return (
                <li key={c.check} className="flex items-start gap-1.5">
                  <Icon className={cn("mt-0.5 size-3.5 shrink-0", tone)} aria-label={c.status} />
                  <span className={cn(c.status === "pass" && "text-muted-foreground")}>
                    {c.label}
                    {c.message && <span className="block text-muted-foreground">{c.message}</span>}
                  </span>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </ResultCard>
  )
}
