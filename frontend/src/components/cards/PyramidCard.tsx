import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { CARD_TOOLTIPS, ConfidenceBadge, ResultCard, type CardState } from "@/components/ResultCard"
import { tierTone } from "@/lib/structure"
import { TIER_STEPS } from "@/lib/lint"
import { cn } from "@/lib/utils"
import type { Advisory, PyramidResult } from "@/lib/types"

const ADVISORY_TITLES: Record<Advisory["kind"], string> = {
  filter: "Exclusion filters are an evasion surface",
  routing: "Routing field floors the tier",
  bare_not: "Negated indicator list",
  level_vs_tier: "High severity, low durability",
}

export function PyramidCard({ state, pyramid }: Readonly<{ state: CardState; pyramid: PyramidResult | null }>) {
  return (
    <ResultCard
      title="Pyramid of Pain"
      tooltip={CARD_TOOLTIPS.pyramid}
      state={state}
      badge={pyramid && state === "ready" ? <ConfidenceBadge confidence={pyramid.confidence} provenance={pyramid.provenance} /> : undefined}
    >
      {pyramid && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className={cn("rounded px-2 py-0.5 text-base font-semibold", tierTone(pyramid.tier))}>
              Tier {pyramid.tier} · {pyramid.tier_name}
            </span>
            <span className="text-xs text-muted-foreground">
              {pyramid.categories.map((c) => c.replace("_", " ")).join(", ")}
            </span>
          </div>

          <ol className="space-y-0.5" aria-label="Pyramid of Pain tiers">
            {TIER_STEPS.map((step) => {
              const active = step.tier === pyramid.tier
              return (
                <li
                  key={step.tier}
                  className={cn(
                    "flex items-center justify-between rounded px-2 py-0.5 text-xs",
                    active ? tierTone(step.tier) : "text-muted-foreground",
                    active && "font-medium ring-1 ring-current/30",
                  )}
                  style={{ marginLeft: `${(6 - step.tier) * 0.5}rem`, marginRight: `${(6 - step.tier) * 0.5}rem` }}
                  aria-current={active ? "true" : undefined}
                >
                  <span>
                    {step.tier} · {step.name}
                  </span>
                  <span className="hidden sm:inline">{step.cost}</span>
                </li>
              )
            })}
          </ol>

          <details className="text-xs" open>
            <summary className="cursor-pointer font-medium">How this was scored</summary>
            <ol className="mt-1 list-decimal space-y-0.5 pl-5 text-muted-foreground">
              {pyramid.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </details>

          {pyramid.advisories.map((a) => (
            <Alert key={`${a.kind}:${a.message}`} className="py-2">
              <AlertTitle className="text-xs">
                <Badge variant="outline" className="mr-1 font-normal">
                  advisory
                </Badge>
                {ADVISORY_TITLES[a.kind]}
              </AlertTitle>
              <AlertDescription className="text-xs">{a.message}</AlertDescription>
            </Alert>
          ))}
        </div>
      )}
    </ResultCard>
  )
}
