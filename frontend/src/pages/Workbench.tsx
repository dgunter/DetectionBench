import { useCallback, useState } from "react"
import { Link } from "react-router-dom"
import { AiPanel } from "@/components/AiPanel"
import { AstCard } from "@/components/cards/AstCard"
import { ExampleChips } from "@/components/ExampleChips"
import { ScopeCard } from "@/components/cards/ScopeCard"
import { CARD_TOOLTIPS, ResultCard, type CardState } from "@/components/ResultCard"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ApiError, api } from "@/lib/api"
import type { ClassifyResponse } from "@/lib/types"

type Phase = "empty" | "loading" | "done"

export function Workbench({ onLoggedOut }: { onLoggedOut: () => void }) {
  const [rule, setRule] = useState("")
  const [phase, setPhase] = useState<Phase>("empty")
  const [result, setResult] = useState<ClassifyResponse | null>(null)
  const [transportError, setTransportError] = useState<string | null>(null)

  async function logout() {
    await api.logout().catch(() => undefined)
    onLoggedOut()
  }

  const classify = useCallback(async () => {
    if (!rule.trim() || phase === "loading") return
    setPhase("loading")
    setTransportError(null)
    try {
      setResult(await api.classify(rule))
    } catch (err) {
      setResult(null)
      if (err instanceof ApiError && err.status === 401) {
        onLoggedOut()
        return
      }
      setTransportError(err instanceof ApiError ? err.message : "Network error.")
    } finally {
      setPhase("done")
    }
  }, [rule, phase, onLoggedOut])

  // Card states: everything loads together; on a parse failure the AST card shows the error and the rest wait.
  const parsed = phase === "done" && result?.ok === true
  const parseFailed = phase === "done" && result !== null && !result.ok
  const astState: CardState = phase === "empty" ? "empty" : phase === "loading" ? "loading" : parseFailed ? "error" : parsed ? "ready" : "empty"
  const dependentState = (ready: boolean): CardState =>
    phase === "empty" ? "empty" : phase === "loading" ? "loading" : parseFailed ? "waiting" : ready ? "ready" : "pending"

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex min-h-svh flex-col">
        <header className="flex items-center justify-between border-b px-4 py-2">
          <div className="flex items-baseline gap-3">
            <span className="font-semibold">DetectionBench</span>
            <span className="text-xs text-muted-foreground">Sigma rule evaluation</span>
          </div>
          <nav className="flex items-center gap-2 text-sm">
            <Link to="/how-it-works" className="text-muted-foreground hover:underline">
              How this works
            </Link>
            <Button variant="ghost" size="sm" onClick={logout}>
              Log out
            </Button>
          </nav>
        </header>

        <section className="border-b bg-muted/30 px-4 py-3">
          <form
            className="flex flex-col gap-2 md:flex-row md:items-end"
            onSubmit={(e) => {
              e.preventDefault()
              void classify()
            }}
          >
            <label className="flex flex-1 flex-col gap-1 text-xs text-muted-foreground">
              Paste a Sigma rule (YAML, one rule, 64 KB max)
              <Textarea
                value={rule}
                onChange={(e) => setRule(e.target.value)}
                onKeyDown={(e) => {
                  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") void classify()
                }}
                spellCheck={false}
                className="min-h-28 font-mono text-xs"
                placeholder={"title: ...\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\evil.exe'\n  condition: selection"}
                aria-label="Sigma rule"
              />
            </label>
            <div className="flex items-center gap-2">
              <Button type="submit" disabled={!rule.trim() || phase === "loading"}>
                {phase === "loading" ? "Classifying…" : "Classify"}
              </Button>
            </div>
          </form>
          <div className="mt-2">
            <ExampleChips
              disabled={phase === "loading"}
              onPick={(yaml) => {
                setRule(yaml)
                setPhase("empty")
                setResult(null)
                setTransportError(null)
              }}
            />
          </div>
          {transportError && (
            <p className="mt-2 text-sm text-destructive" role="alert">
              {transportError}
            </p>
          )}
        </section>

        <main className="grid flex-1 gap-3 p-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <div className="grid gap-3 md:grid-cols-2">
            <AstCard state={astState} ast={result?.ast ?? null} error={result?.error ?? null} />
            <ScopeCard state={dependentState(Boolean(result?.scope))} scope={result?.scope ?? null} />
            <ResultCard title="Pyramid of Pain" tooltip={CARD_TOOLTIPS.pyramid} state={dependentState(false)} />
            <ResultCard title="Lint results" tooltip={CARD_TOOLTIPS.lint} state={dependentState(false)} />
            <ResultCard title="ATT&CK mapping" tooltip={CARD_TOOLTIPS.attack} state={dependentState(false)} className="md:col-span-2" />
          </div>
          <AiPanel hasRule={parsed} />
        </main>
      </div>
    </TooltipProvider>
  )
}
