import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { api, type Example } from "@/lib/api"

/** Example-rule chips for the top bar. Calls onPick with the rule YAML. */
export function ExampleChips({ onPick, disabled }: { onPick: (yaml: string, example: Example) => void; disabled?: boolean }) {
  const [examples, setExamples] = useState<Example[]>([])

  useEffect(() => {
    let cancelled = false
    api
      .examples()
      .then((list) => {
        if (!cancelled) setExamples(list)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [])

  if (examples.length === 0) return null

  return (
    <div className="flex flex-wrap items-center gap-1.5" aria-label="Example rules">
      <span className="text-xs text-muted-foreground">Examples:</span>
      {examples.map((ex) => (
        <Tooltip key={ex.id}>
          <TooltipTrigger asChild>
            <Button type="button" variant="outline" size="sm" className="h-7 rounded-full px-3 text-xs" disabled={disabled} onClick={() => onPick(ex.yaml, ex)}>
              {ex.label}
            </Button>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">
            <p className="font-medium">{ex.title}</p>
            <p className="text-xs opacity-80">{ex.blurb}</p>
          </TooltipContent>
        </Tooltip>
      ))}
    </div>
  )
}
