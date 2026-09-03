import { Info } from "lucide-react"
import type { ReactNode } from "react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import { confidenceTone, provenanceLabel } from "@/lib/ast"
import type { Confidence } from "@/lib/types"

export type CardState = "empty" | "loading" | "waiting" | "error" | "ready" | "pending"

/** One-line copy from the methodology page, shown on the info icon. */
export const CARD_TOOLTIPS = {
  ast: "The rule's logic, broken into its structural pieces.",
  scope: "Plain-language read of what this rule actually matches, derived from the same parsed logic.",
  pyramid: "How durable this detection is — see 'How this works' for the full framework.",
  lint: "Metadata completeness check — separate from whether the detection logic itself is strong.",
  attack: "Declared technique IDs, checked against a real offline copy of MITRE ATT&CK.",
  confidence: "How sure we are, and whether this came from parsing the rule, reading its metadata, or an AI guess.",
} as const

export function ConfidenceBadge({ confidence, provenance }: { confidence: Confidence; provenance: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="flex items-center gap-1">
          <Badge variant="outline" className={cn("font-normal", confidenceTone(confidence))}>
            {confidence} confidence
          </Badge>
          <Badge variant="secondary" className="font-normal">
            {provenanceLabel(provenance)}
          </Badge>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{CARD_TOOLTIPS.confidence}</TooltipContent>
    </Tooltip>
  )
}

export function ResultCard({
  title,
  tooltip,
  state,
  badge,
  className,
  children,
}: {
  title: string
  tooltip: string
  state: CardState
  badge?: ReactNode
  className?: string
  children?: ReactNode
}) {
  return (
    <Card className={cn("gap-3 py-4", className)} data-state={state}>
      <CardHeader className="px-4">
        <CardTitle className="flex items-center gap-1.5 text-sm font-semibold">
          {title}
          <Tooltip>
            <TooltipTrigger asChild>
              <Info className="size-3.5 text-muted-foreground" aria-label={`About ${title}`} />
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">{tooltip}</TooltipContent>
          </Tooltip>
        </CardTitle>
        {badge && <div className="col-start-2 row-span-2 row-start-1 self-start justify-self-end">{badge}</div>}
      </CardHeader>
      <CardContent className="px-4 text-sm">
        {state === "empty" && <p className="text-muted-foreground">Paste a rule and click Classify.</p>}
        {state === "loading" && (
          <div className="space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        )}
        {state === "waiting" && <p className="text-muted-foreground">Waiting for a rule that parses.</p>}
        {state === "pending" && <p className="text-muted-foreground">This card is being wired up.</p>}
        {(state === "ready" || state === "error") && children}
      </CardContent>
    </Card>
  )
}
