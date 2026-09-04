import { AlertTriangle, ExternalLink, Info } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { TOOLTIPS, PROVENANCE_LABELS } from "@/lib/copy"
import { summarizeAttack, type AttackMapping, type TechniqueRef } from "@/lib/attack"

function TechniqueRow({ t }: Readonly<{ t: TechniqueRef }>) {
  const tone =
    t.status === "valid" ? "secondary" : t.status === "retired" ? "outline" : ("destructive" as const)
  const replacedByName = t.replaced_by_name ? ` (${t.replaced_by_name})` : ""
  const replacedBy = t.replaced_by ? ` → ${t.replaced_by}${replacedByName}` : ""
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm">
      <Badge variant={tone} className="font-mono">
        {t.id}
      </Badge>
      {t.name ? (
        <span>{t.name}</span>
      ) : (
        <span className="text-destructive">not in ATT&CK Enterprise</span>
      )}
      {t.status === "retired" && (
        <span className="text-muted-foreground">
          retired{replacedBy}
        </span>
      )}
      {t.tactics.length > 0 && (
        <span className="text-xs text-muted-foreground">{t.tactics.join(", ")}</span>
      )}
      {t.url && (
        <a href={t.url} target="_blank" rel="noreferrer" className="text-muted-foreground hover:text-foreground" aria-label={`${t.id} on attack.mitre.org`}>
          <ExternalLink className="size-3.5" />
        </a>
      )}
    </li>
  )
}

export function AttackCard({ mapping }: Readonly<{ mapping: AttackMapping }>) {
  const issues = mapping.findings.filter((f) => f.severity !== "info")
  const notes = mapping.findings.filter((f) => f.severity === "info")
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          ATT&CK mapping
          <Tooltip>
            <TooltipTrigger asChild>
              <Info className="size-4 text-muted-foreground" aria-label="About this card" />
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">{TOOLTIPS.attack}</TooltipContent>
          </Tooltip>
        </CardTitle>
        <CardDescription className="flex flex-wrap items-center gap-2">
          <span>{summarizeAttack(mapping)}</span>
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="outline" className="font-normal">
                {PROVENANCE_LABELS[mapping.provenance] ?? mapping.provenance} · {mapping.confidence}
              </Badge>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">{TOOLTIPS.confidence}</TooltipContent>
          </Tooltip>
          <span className="text-xs">ATT&CK v{mapping.dataset_version}</span>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {mapping.techniques.length > 0 && (
          <ul className="space-y-1.5">
            {mapping.techniques.map((t) => (
              <TechniqueRow key={t.tag} t={t} />
            ))}
          </ul>
        )}
        {mapping.tactics.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {mapping.tactics.map((t) => (
              <Badge key={t.tag} variant={t.status === "unknown" ? "destructive" : "secondary"}>
                {t.name}
                {t.status === "renamed" && t.renamed_to ? ` → ${t.renamed_to}` : ""}
              </Badge>
            ))}
          </div>
        )}
        {mapping.unvalidated.length > 0 && (
          <p className="text-xs text-muted-foreground">
            Software/group tags not validated in v1: {mapping.unvalidated.join(", ")}
          </p>
        )}
        {issues.length > 0 && (
          <ul className="space-y-1 text-sm">
            {issues.map((f) => (
              <li key={`${f.check}:${f.tag ?? ""}:${f.message}`} className="flex items-start gap-2">
                <AlertTriangle className={`mt-0.5 size-4 shrink-0 ${f.severity === "error" ? "text-destructive" : "text-amber-600"}`} />
                <span>{f.message}</span>
              </li>
            ))}
          </ul>
        )}
        {notes.length > 0 && issues.length === 0 && mapping.unvalidated.length === 0 && (
          <p className="text-xs text-muted-foreground">{notes.map((n) => n.message).join("; ")}</p>
        )}
        {mapping.declared_count === 0 && (
          <p className="text-sm text-muted-foreground">
            The rule declares no ATT&CK tags. Ask the AI panel to suggest techniques, then verify them here.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
