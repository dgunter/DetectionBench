import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

const MODELS = [
  { id: "opus", label: "Claude Opus", enabled: true },
  { id: "sonnet", label: "Claude Sonnet", enabled: false },
  { id: "fable", label: "Claude Fable", enabled: false },
] as const

const ACTIONS = ["Explain this rule", "Suggest ATT&CK techniques", "Generate 3 candidate rules"] as const

/** Right-hand AI second-opinion panel. Actions are wired in a later step; the shell fixes the layout now. */
export function AiPanel({ hasRule }: { hasRule: boolean }) {
  return (
    <Card className="h-full gap-3 py-4">
      <CardHeader className="px-4">
        <CardTitle className="text-sm font-semibold">AI second opinion</CardTitle>
        <CardDescription className="text-xs">
          Shown alongside the deterministic cards, never merged into them.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 px-4 text-sm">
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="flex flex-wrap gap-1" role="radiogroup" aria-label="Model">
              {MODELS.map((m) => (
                <Button key={m.id} size="sm" variant={m.enabled ? "secondary" : "ghost"} disabled={!m.enabled} aria-pressed={m.enabled}>
                  {m.label}
                  {!m.enabled && <span className="text-[10px] text-muted-foreground">soon</span>}
                </Button>
              ))}
            </div>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">
            Pick which Claude model answers — the deterministic cards don't change no matter which you choose.
          </TooltipContent>
        </Tooltip>
        <div className="flex flex-col gap-2">
          {ACTIONS.map((a) => (
            <Button key={a} variant="outline" size="sm" disabled title="Available once the AI panel is wired">
              {a}
            </Button>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">{hasRule ? "AI actions arrive in a later step." : "Classify a rule first."}</p>
      </CardContent>
    </Card>
  )
}
