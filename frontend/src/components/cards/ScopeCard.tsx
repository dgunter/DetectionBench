import { Badge } from "@/components/ui/badge"
import { CARD_TOOLTIPS, ConfidenceBadge, ResultCard, type CardState } from "@/components/ResultCard"
import { cn, keyed } from "@/lib/utils"
import type { ScopeResult } from "@/lib/types"

export function ScopeCard({ state, scope }: Readonly<{ state: CardState; scope: ScopeResult | null }>) {
  return (
    <ResultCard
      title="Scope & match"
      tooltip={CARD_TOOLTIPS.scope}
      state={state}
      badge={scope && state === "ready" ? <ConfidenceBadge confidence={scope.confidence} provenance={scope.provenance} /> : undefined}
    >
      {scope && (
        <div className="space-y-3">
          <p>{scope.summary}</p>
          <ol className="space-y-0.5 text-xs">
            {keyed(scope.outline, (l) => `${l.depth}:${l.role}:${l.text}`).map(({ key, item: line }) => (
              <li
                key={key}
                style={{ paddingLeft: `${line.depth * 1.25}rem` }}
                className={cn(
                  line.role === "filter" && "text-amber-800 dark:text-amber-300",
                  line.role === "not" && "text-amber-800 dark:text-amber-300",
                  (line.role === "and" || line.role === "or") && "text-muted-foreground",
                  line.role === "criterion" && "font-mono",
                )}
              >
                {line.text}
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <span>{scope.logsource_text}</span>
            <span>·</span>
            <span>{scope.criteria_count} criteria</span>
            {scope.filter_count > 0 && (
              <>
                <span>·</span>
                <span>{scope.filter_count} exclusion filter(s)</span>
              </>
            )}
          </div>
          <div className="flex flex-wrap gap-1">
            {scope.selections.map((s) => (
              <Badge key={s.name} variant={s.role === "filter" ? "outline" : "secondary"} className="font-mono font-normal">
                {s.name} · {s.criteria}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </ResultCard>
  )
}
