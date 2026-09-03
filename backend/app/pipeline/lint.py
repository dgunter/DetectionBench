"""Lint: metadata completeness, independent of whether the detection logic is any good.

Two sources merged into one findings list, all ``confidence: high`` (binary checks):

1. The check table below, run against the **raw YAML dict** so a rule pySigma
   partly rejects still gets its other findings.
2. pySigma's ``rule.errors`` (from ``collect_errors=True``), mapped onto the
   same check keys so nothing is reported twice.

ATT&CK tag findings come from ``attack_map`` (one place, reported once) and
are merged in as well.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from sigma.exceptions import SigmaError

from app.pipeline.attack import AttackDataset
from app.pipeline.attack_map import Finding, map_attack_tags
from app.pipeline.ir import RuleIR

Status = Literal["pass", "error", "warning", "info"]

VALID_STATUS = ("stable", "test", "experimental", "deprecated", "unsupported")
VALID_LEVEL = ("informational", "low", "medium", "high", "critical")
TRIVIAL_FALSEPOSITIVES = {"unknown", "none", "n/a", "na", "-", ""}
MIN_DESCRIPTION_CHARS = 20

# (check, human label) in table order. Every check appears in the result, pass or fail.
CHECK_TABLE: tuple[tuple[str, str], ...] = (
    ("title", "title present"),
    ("id", "id is a valid UUID"),
    ("status", "status present and valid"),
    ("description", "description present and non-trivial"),
    ("references", "references present"),
    ("level", "level present and valid"),
    ("falsepositives", "falsepositives present, not just 'Unknown'"),
    ("logsource", "logsource category/product populated"),
    ("selections", "every selection is used by the condition"),
    ("attack_techniques", "attack.t* technique tags resolve"),
    ("attack_tactics", "attack.<tactic> tags resolve"),
    ("attack_software_groups", "attack.s*/g* tags (not validated in v1)"),
    ("date", "date/modified are valid dates"),
)

# pySigma metadata errors -> (check, severity). Anything not listed falls back to a generic warning.
PYSIGMA_ERROR_MAP: dict[str, tuple[str, str]] = {
    "SigmaTitleError": ("title", "error"),
    "SigmaIdentifierError": ("id", "error"),
    "SigmaStatusError": ("status", "warning"),
    "SigmaDescriptionError": ("description", "warning"),
    "SigmaReferencesError": ("references", "warning"),
    "SigmaLevelError": ("level", "error"),
    "SigmaFalsePositivesError": ("falsepositives", "warning"),
    "SigmaLogsourceError": ("logsource", "error"),
    "SigmaDateError": ("date", "warning"),
    "SigmaModifiedError": ("date", "warning"),
    "SigmaTagError": ("attack_techniques", "error"),
}


@dataclass(frozen=True)
class CheckRow:
    check: str
    label: str
    status: Status
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "label": self.label, "status": self.status, "message": self.message}


@dataclass(frozen=True)
class LintResult:
    checks: tuple[CheckRow, ...]
    findings: tuple[Finding, ...]
    provenance: str = "deterministic:metadata"
    confidence: str = "high"

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def value(self) -> str:
        parts = []
        for severity in ("error", "warning", "info"):
            n = self.count(severity)
            if n:
                parts.append(f"{n} {severity}{'s' if n != 1 else ''}")
        return ", ".join(parts) if parts else "clean"

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings],
            "counts": {"error": self.count("error"), "warning": self.count("warning"), "info": self.count("info")},
            "passed": sum(1 for c in self.checks if c.status == "pass"),
            "provenance": self.provenance,
            "confidence": self.confidence,
            "rationale": "Binary checks against the author-declared metadata and the resolved condition; severity is separate from the Pyramid of Pain tier.",
        }


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [_text(v) for v in value if _text(v)]
    return [_text(value)] if _text(value) else []


def _metadata_checks(raw: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    title = _text(raw.get("title"))
    if not title:
        out.append(Finding("title", "error", "title is missing", "title"))

    rule_id = _text(raw.get("id"))
    if not rule_id:
        out.append(Finding("id", "error", "id is missing; Sigma rules are identified by a UUID", "id"))
    else:
        try:
            uuid.UUID(rule_id)
        except ValueError:
            out.append(Finding("id", "error", f"id '{rule_id}' is not a valid UUID", "id"))

    status = _text(raw.get("status")).lower()
    if not status:
        out.append(Finding("status", "warning", "status is missing (stable, test, experimental, deprecated, unsupported)", "status"))
    elif status not in VALID_STATUS:
        out.append(Finding("status", "warning", f"status '{status}' is not one of {', '.join(VALID_STATUS)}", "status"))

    description = _text(raw.get("description"))
    if not description:
        out.append(Finding("description", "warning", "description is missing", "description"))
    elif len(description) < MIN_DESCRIPTION_CHARS or description.lower() == title.lower():
        out.append(Finding("description", "warning", "description is trivial (under 20 characters or identical to the title)", "description"))

    if not _list(raw.get("references")):
        out.append(Finding("references", "warning", "references are missing; analysts need a source to triage against", "references"))

    level = _text(raw.get("level")).lower()
    if not level:
        out.append(Finding("level", "error", "level is missing (informational, low, medium, high, critical)", "level"))
    elif level not in VALID_LEVEL:
        out.append(Finding("level", "error", f"level '{level}' is not one of {', '.join(VALID_LEVEL)}", "level"))

    falsepositives = [fp.lower() for fp in _list(raw.get("falsepositives"))]
    if not falsepositives:
        out.append(Finding("falsepositives", "warning", "falsepositives are missing", "falsepositives"))
    elif all(fp in TRIVIAL_FALSEPOSITIVES for fp in falsepositives):
        out.append(Finding("falsepositives", "warning", "falsepositives only say 'Unknown'; note what benign activity could trigger this", "falsepositives"))

    logsource = raw.get("logsource")
    if not isinstance(logsource, dict) or not any(_text(logsource.get(k)) for k in ("category", "product", "service")):
        out.append(Finding("logsource", "error", "logsource is missing; category, product or service is required", "logsource"))
    elif not (_text(logsource.get("category")) or _text(logsource.get("product"))):
        out.append(Finding("logsource", "warning", "logsource has only a service; category/product should be populated", "logsource"))
    return out


def _selection_checks(ir: RuleIR, defined: list[str]) -> list[Finding]:
    used = set(ir.selections)
    unused = [name for name in defined if name not in used and name != "condition"]
    if unused:
        names = ", ".join(f"'{n}'" for n in unused)
        return [Finding("selections", "warning", f"selection(s) {names} are defined but never used by the condition", None)]
    return []


def _pysigma_findings(errors: tuple[SigmaError, ...], already: set[str]) -> list[Finding]:
    out: list[Finding] = []
    for err in errors:
        name = type(err).__name__
        check, severity = PYSIGMA_ERROR_MAP.get(name, ("pysigma", "warning"))
        if check in already:
            continue  # the raw-dict check already reported this row
        already.add(check)
        out.append(Finding(check, severity, f"pySigma: {err}", None))
    return out


def lint_rule(
    raw: dict[str, Any],
    ir: RuleIR,
    defined_selections: list[str],
    metadata_errors: tuple[SigmaError, ...],
    dataset: AttackDataset,
) -> LintResult:
    findings = _metadata_checks(raw)
    findings += _selection_checks(ir, defined_selections)
    reported = {f.check for f in findings}
    findings += _pysigma_findings(metadata_errors, reported)

    attack = map_attack_tags(ir.metadata.tags, dataset)
    findings += list(attack.findings)

    # Build the fixed table: every check, pass or worst finding.
    attack_rows = {
        "attack_techniques": ("attack_technique_unknown", "attack_technique_retired", "attack_tag_malformed", "attack_tag_duplicate"),
        "attack_tactics": ("attack_tactic_unknown", "attack_tactic_renamed"),
        "attack_software_groups": ("attack_software_group_tag",),
    }
    rank = {"error": 3, "warning": 2, "info": 1}
    rows: list[CheckRow] = []
    for check, label in CHECK_TABLE:
        keys = attack_rows.get(check, (check,))
        hits = [f for f in findings if f.check in keys]
        if not hits:
            rows.append(CheckRow(check, label, "pass"))
            continue
        worst = max(hits, key=lambda f: rank[f.severity])
        rows.append(CheckRow(check, label, worst.severity, "; ".join(h.message for h in hits)))

    return LintResult(checks=tuple(rows), findings=tuple(findings))
