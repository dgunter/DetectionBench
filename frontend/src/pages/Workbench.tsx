import { useCallback, useState } from "react"
import { Link } from "react-router-dom"
import { AiPanel } from "@/components/AiPanel"
import { ThemeToggle } from "@/components/ThemeToggle"
import { StructureCard } from "@/components/cards/StructureCard"
import { AttackCard } from "@/components/cards/AttackCard"
import { LintCard } from "@/components/cards/LintCard"
import { PyramidCard } from "@/components/cards/PyramidCard"
import { ExampleChips } from "@/components/ExampleChips"
import { ScopeCard } from "@/components/cards/ScopeCard"
import { CARD_TOOLTIPS, ResultCard, type CardState } from "@/components/ResultCard"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ApiError, api } from "@/lib/api"
import type { ClassifyResponse } from "@/lib/types"

type Phase = "empty" | "loading" | "done"

export function Workbench({ onLoggedOut }: Readonly<{ onLoggedOut: () => void }>) {
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

  // Card states: everything loads together; on a parse failure the Parsed structure card shows the error and the rest wait.
  const parsed = phase === "done" && result?.ok === true
  const parseFailed = phase === "done" && result !== null && !result.ok
  const structureState: CardState = phase === "empty" ? "empty" : phase === "loading" ? "loading" : parseFailed ? "error" : parsed ? "ready" : "empty"
  const dependentState = (ready: boolean): CardState =>
    phase === "empty" ? "empty" : phase === "loading" ? "loading" : parseFailed ? "waiting" : ready ? "ready" : "pending"

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex min-h-svh flex-col">
        <header className="flex items-center justify-between border-b px-4 py-2">
          <div className="flex items-center gap-2">
            <img src="/logo.png" alt="" className="size-6" />
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
            <ThemeToggle />
          </nav>
        </header>

        <main className="grid flex-1 gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)_minmax(0,0.85fr)] lg:items-start">
          {/* Column 1: the rule. Long rules scroll inside the editor instead of pushing the results down. */}
          <section className="flex flex-col gap-2 lg:sticky lg:top-4 lg:max-h-[calc(100svh-2rem)]">
            <form
              className="flex min-h-0 flex-1 flex-col gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                void classify()
              }}
            >
              <label className="flex min-h-0 flex-1 flex-col gap-1 text-xs text-muted-foreground">
                Paste a Sigma rule (YAML, one rule, 64 KB max)
                <Textarea
                  value={rule}
                  onChange={(e) => setRule(e.target.value)}
                  onKeyDown={(e) => {
                    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") void classify()
                  }}
                  spellCheck={false}
                  className="min-h-[24rem] flex-1 resize-none overflow-auto font-mono text-xs lg:max-h-[calc(100svh-11rem)]"
                  placeholder={"title: ...\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\evil.exe'\n  condition: selection"}
                  aria-label="Sigma rule"
                />
              </label>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground">{rule.trim() ? `${rule.length.toLocaleString()} characters` : "\u00a0"}</span>
                <Button type="submit" disabled={!rule.trim() || phase === "loading"}>
                  {phase === "loading" ? "Classifying…" : "Classify"}
                </Button>
              </div>
            </form>
            <ExampleChips
              disabled={phase === "loading"}
              onPick={(yaml) => {
                setRule(yaml)
                setPhase("empty")
                setResult(null)
                setTransportError(null)
              }}
            />
            {transportError && (
              <p className="text-sm text-destructive" role="alert">
                {transportError}
              </p>
            )}
          </section>

          {/* Column 2: the five deterministic cards, in pipeline order. */}
          <div className="flex flex-col gap-3">
            <StructureCard state={structureState} structure={result?.structure ?? null} error={result?.error ?? null} />
            <ScopeCard state={dependentState(Boolean(result?.scope))} scope={result?.scope ?? null} />
            <PyramidCard state={dependentState(Boolean(result?.pyramid))} pyramid={result?.pyramid ?? null} />
            <LintCard state={dependentState(Boolean(result?.lint))} lint={result?.lint ?? null} />
            {parsed && result?.attack ? (
              <AttackCard mapping={result.attack} />
            ) : (
              <ResultCard title="ATT&CK mapping" tooltip={CARD_TOOLTIPS.attack} state={dependentState(false)} />
            )}
          </div>

          {/* Column 3: the AI second opinion, never merged into column 2. */}
          <div className="lg:sticky lg:top-4">
            <AiPanel
              hasRule={parsed}
              rule={rule}
              onUseCandidate={(yaml) => {
                setRule(yaml)
                setPhase("empty")
                setResult(null)
                setTransportError(null)
              }}
            />
          </div>
        </main>
      </div>
    </TooltipProvider>
  )
}
