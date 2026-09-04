import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { CARD_TOOLTIPS, ConfidenceBadge, ResultCard, type CardState } from "@/components/ResultCard"
import { flattenAst, tierTone } from "@/lib/ast"
import { cn } from "@/lib/utils"
import type { AstResult, ParseFailure } from "@/lib/types"

const PARSE_ERROR_TITLES: Record<string, string> = {
  too_large: "Rule is too large",
  invalid_yaml: "Not valid YAML",
  empty: "Nothing to classify",
  not_a_mapping: "Not a Sigma rule",
  multiple_rules: "One rule at a time",
  correlation_rule: "Correlation rules aren't supported in v1",
  invalid_condition: "Condition doesn't resolve",
  invalid_detection: "Detection section can't be parsed",
  invalid_modifier: "Unknown field modifier",
  invalid_value: "Unsupported value",
}

export function AstCard({ state, ast, error }: Readonly<{ state: CardState; ast: AstResult | null; error: ParseFailure | null }>) {
  return (
    <ResultCard
      title="Parsed AST"
      tooltip={CARD_TOOLTIPS.ast}
      state={state}
      badge={ast && state === "ready" ? <ConfidenceBadge confidence={ast.confidence} provenance={ast.provenance} /> : undefined}
    >
      {state === "error" && error && (
        <Alert variant="destructive">
          <AlertTitle>{PARSE_ERROR_TITLES[error.code] ?? "Parse error"}</AlertTitle>
          <AlertDescription>
            <p>{error.message}</p>
            {error.detail && <p className="font-mono text-xs break-all">{error.detail}</p>}
          </AlertDescription>
        </Alert>
      )}
      {state === "ready" && ast && <AstTree ast={ast} />}
    </ResultCard>
  )
}

function AstTree({ ast }: Readonly<{ ast: AstResult }>) {
  const lines = flattenAst(ast.root)
  return (
    <div className="space-y-2">
      <p className="font-mono text-xs text-muted-foreground">
        condition: <span className="text-foreground">{ast.condition}</span>
      </p>
      <ol className="space-y-0.5 font-mono text-xs">
        {lines.map((line) => (
          <li key={line.path} className="flex flex-wrap items-center gap-1.5" style={{ paddingLeft: `${line.depth * 1.25}rem` }}>
            {line.kind === "boolean" ? (
              <>
                <Badge variant="outline" className="font-mono">
                  {line.label}
                </Badge>
                {line.selection && <span className="text-muted-foreground">{line.selection}</span>}
              </>
            ) : (
              line.criterion && (
                <>
                  <span className="text-foreground">{line.label}</span>
                  <span className="text-muted-foreground">=</span>
                  <span className="break-all text-foreground/80">{formatValues(line.criterion.values)}</span>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span
                        className={cn("rounded px-1 py-px text-[10px] leading-4", tierTone(line.criterion.tier))}
                        aria-label={`tier ${line.criterion.tier}`}
                      >
                        T{line.criterion.tier} · {line.criterion.category.replace("_", " ")}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs">
                      {line.criterion.tier_name}
                      {line.criterion.note ? ` — ${line.criterion.note}` : ""}
                    </TooltipContent>
                  </Tooltip>
                </>
              )
            )}
          </li>
        ))}
      </ol>
      {ast.metadata_errors.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {ast.metadata_errors.length} metadata problem(s) found by pySigma; see the Lint card.
        </p>
      )}
    </div>
  )
}

/** Show values as the author wrote them (Sigma single quotes), not JSON-escaped. */
function formatValues(values: string[]): string {
  const q = (v: string) => `'${v.replaceAll("'", String.raw`\'`)}'`
  if (values.length === 1) return q(values[0])
  return `[${values.map(q).join(", ")}]`
}
