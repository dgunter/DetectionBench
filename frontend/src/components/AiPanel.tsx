import { useEffect, useState } from "react"
import { AlertTriangle, ExternalLink, Loader2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { ApiError, api } from "@/lib/api"
import { TOOLTIPS } from "@/lib/copy"
import {
  describeDelta,
  describeLlmError,
  type CandidatesResult,
  type ExplainResult,
  type LlmAction,
  type ModelKey,
  type SuggestAttackResult,
} from "@/lib/llm"

const MODELS: { id: ModelKey; label: string; enabled: boolean }[] = [
  { id: "opus", label: "Claude Opus", enabled: true },
  { id: "sonnet", label: "Claude Sonnet", enabled: false },
  { id: "fable", label: "Claude Fable", enabled: false },
]

const ACTIONS: { id: LlmAction; label: string }[] = [
  { id: "explain", label: "Explain this rule" },
  { id: "suggest_attack", label: "Suggest ATT&CK techniques" },
  { id: "candidates", label: "Generate 3 candidate rules" },
]

type PanelResult = ExplainResult | SuggestAttackResult | CandidatesResult

interface Props {
  /** True once the deterministic pipeline has parsed the current rule. */
  hasRule: boolean
  /** The rule text to send. Actions stay disabled until it is provided. */
  rule?: string
  /** Called with a candidate's YAML when the user wants to load it into the editor. */
  onUseCandidate?: (yaml: string) => void
}

/** Right-hand AI second-opinion panel. Output is rendered as plain text only. */
export function AiPanel({ hasRule, rule, onUseCandidate }: Props) {
  const [model, setModel] = useState<ModelKey>("opus")
  const [busy, setBusy] = useState<LlmAction | null>(null)
  const [result, setResult] = useState<PanelResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [budget, setBudget] = useState<{ remaining: number; limit: number } | null>(null)

  const ready = hasRule && Boolean(rule?.trim())

  // Reset when the rule changes so a stale answer never sits next to a new rule.
  useEffect(() => {
    setResult(null)
    setError(null)
  }, [rule])

  useEffect(() => {
    api.llmBudget().then(setBudget).catch(() => undefined)
  }, [result])

  async function run(action: LlmAction) {
    if (!ready || busy || !rule) return
    setBusy(action)
    setError(null)
    setResult(null)
    try {
      if (action === "explain") setResult(await api.llmExplain(rule, model))
      else if (action === "suggest_attack") setResult(await api.llmSuggestAttack(rule, model))
      else setResult(await api.llmCandidates(rule, model))
    } catch (err) {
      if (err instanceof ApiError) setError(describeLlmError(err.status, err.code, err.message))
      else setError("Network error.")
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card className="h-full gap-3 py-4">
      <CardHeader className="px-4">
        <CardTitle className="flex items-center justify-between text-sm font-semibold">
          <span>AI second opinion</span>
          <Badge variant="outline" className="font-normal">
            Inferred · LLM
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs">Shown alongside the deterministic cards, never merged into them.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 px-4 text-sm">
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="flex flex-wrap gap-1" role="radiogroup" aria-label="Model">
              {MODELS.map((m) => (
                <Button
                  key={m.id}
                  size="sm"
                  variant={model === m.id ? "secondary" : "ghost"}
                  disabled={!m.enabled || busy !== null}
                  aria-pressed={model === m.id}
                  onClick={() => setModel(m.id)}
                >
                  {m.label}
                  {!m.enabled && <span className="text-[10px] text-muted-foreground">soon</span>}
                </Button>
              ))}
            </div>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">{TOOLTIPS.modelSelector}</TooltipContent>
        </Tooltip>

        <div className="flex flex-col gap-2">
          {ACTIONS.map((a) => (
            <Button key={a.id} variant="outline" size="sm" disabled={!ready || busy !== null} onClick={() => void run(a.id)}>
              {busy === a.id && <Loader2 className="size-3.5 animate-spin" />}
              {a.label}
            </Button>
          ))}
        </div>

        {!ready && <p className="text-xs text-muted-foreground">Classify a rule first.</p>}
        {busy && <p className="text-xs text-muted-foreground">Asking the model… this can take up to a minute.</p>}

        {error && (
          <p className="flex items-start gap-2 text-sm text-destructive" role="alert">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </p>
        )}

        {result?.action === "explain" && <p className="whitespace-pre-wrap leading-relaxed">{result.text}</p>}

        {result?.action === "suggest_attack" && (
          <div className="space-y-2">
            <p className="text-xs text-muted-foreground">IDs checked against ATT&CK v{result.dataset_version}.</p>
            {result.suggestions.length === 0 && <p className="text-muted-foreground">No techniques suggested.</p>}
            <ul className="space-y-2">
              {result.suggestions.map((s) => (
                <li key={s.id} className="rounded-md border p-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={s.status === "valid" ? "secondary" : s.status === "retired" ? "outline" : "destructive"} className="font-mono">
                      {s.id}
                    </Badge>
                    <span className="font-medium">{s.name}</span>
                    {s.already_declared && <span className="text-xs text-muted-foreground">already declared</span>}
                    {s.status === "retired" && (
                      <span className="text-xs text-muted-foreground">retired{s.replaced_by ? ` → ${s.replaced_by}` : ""}</span>
                    )}
                    {s.status === "unknown" && <span className="text-xs text-destructive">not a real technique ID</span>}
                    <span className="ml-auto text-xs text-muted-foreground">{s.confidence}</span>
                    {s.url && (
                      <a href={s.url} target="_blank" rel="noreferrer" aria-label={`${s.id} on attack.mitre.org`} className="text-muted-foreground hover:text-foreground">
                        <ExternalLink className="size-3.5" />
                      </a>
                    )}
                  </div>
                  <p className="mt-1 whitespace-pre-wrap text-xs text-muted-foreground">{s.rationale}</p>
                </li>
              ))}
            </ul>
          </div>
        )}

        {result?.action === "candidates" && (
          <div className="space-y-2">
            <p className="text-xs text-muted-foreground">
              Each candidate was re-run through the deterministic pipeline. Original: {result.original.tier_name ?? "unscored"}.
              Under the AND rule, "tier preserved, fewer false positives, lint clean" is the normal win.
            </p>
            {result.candidates.map((c) => (
              <div key={c.index} className={`rounded-md border p-2 ${c.is_win ? "" : "opacity-70"}`}>
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge variant={c.verdict === "raised" ? "default" : c.verdict === "preserved" ? "secondary" : "destructive"}>
                    {c.verdict === "raised" ? "Tier raised" : c.verdict === "preserved" ? "Win" : c.verdict === "regressed" ? "Regressed" : "Discarded"}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{describeDelta(c)}</span>
                  {c.is_win && onUseCandidate && (
                    <Button variant="ghost" size="sm" className="ml-auto h-6 px-2 text-xs" onClick={() => onUseCandidate(c.yaml)}>
                      Load into editor
                    </Button>
                  )}
                </div>
                <p className="mt-1 text-xs">{c.label}</p>
                {c.strategy && <p className="mt-1 whitespace-pre-wrap text-xs text-muted-foreground">{c.strategy}</p>}
                {c.is_win && (
                  <details className="mt-1">
                    <summary className="cursor-pointer text-xs text-muted-foreground">Show rule</summary>
                    <pre className="mt-1 max-h-64 overflow-auto rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">{c.yaml}</pre>
                  </details>
                )}
              </div>
            ))}
          </div>
        )}

        {budget && (
          <p className="text-[11px] text-muted-foreground">
            Shared hourly budget: {budget.remaining} of {budget.limit} calls left.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
