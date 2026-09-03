"""Scope & match: a plain-language description generated from the IR.

Symbolic only in v1: no execution against real telemetry. Output is a nested
outline (one entry per node, with depth) plus a one-paragraph summary, so the
card can render structure rather than a wall of text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.pipeline.ir import Boolean, Criterion, Node, RuleIR, iter_criteria
from app.pipeline.pyramid import is_filter

_MODIFIER_PHRASES = {
    "contains": "contains",
    "startswith": "starts with",
    "endswith": "ends with",
    "re": "matches regex",
    "cidr": "is inside network",
    "fieldref": "equals the value of field",
    "gt": "is greater than",
    "gte": "is at least",
    "lt": "is less than",
    "lte": "is at most",
    "exists": "exists",
    "base64": "contains base64 of",
    "base64offset": "contains base64 (any offset) of",
    "windash": "contains (any dash variant)",
    "wide": "as UTF-16",
    "utf16": "as UTF-16",
    "utf16be": "as UTF-16BE",
    "cased": "(case-sensitive)",
    "expand": "expands placeholder",
}
_MAX_LISTED_VALUES = 4


@dataclass(frozen=True)
class OutlineLine:
    depth: int
    text: str
    role: str  # criterion | and | or | not | filter
    selection: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"depth": self.depth, "text": self.text, "role": self.role, "selection": self.selection}


@dataclass(frozen=True)
class ScopeResult:
    summary: str
    logsource_text: str
    outline: tuple[OutlineLine, ...]
    fields: tuple[str, ...]
    selections: tuple[dict[str, Any], ...]
    criteria_count: int
    filter_count: int
    provenance: str = "deterministic:ast"
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.summary,
            "summary": self.summary,
            "logsource_text": self.logsource_text,
            "outline": [line.to_dict() for line in self.outline],
            "fields": list(self.fields),
            "selections": list(self.selections),
            "criteria_count": self.criteria_count,
            "filter_count": self.filter_count,
            "provenance": self.provenance,
            "confidence": self.confidence,
            "rationale": "Derived symbolically from the parsed condition tree; not executed against telemetry.",
        }


def logsource_text(ir: RuleIR) -> str:
    ls = ir.metadata.logsource
    parts = [p for p in (ls.product, ls.category or ls.service) if p]
    if ls.category and ls.service:
        parts = [p for p in (ls.product, ls.service, ls.category) if p]
    return " ".join(parts) + " events" if parts else "events from an unspecified log source"


def _quote(v: str) -> str:
    return "'" + v.replace("'", "\\'") + "'"


def _values_phrase(values: tuple[str, ...]) -> str:
    if len(values) == 1:
        return _quote(values[0])
    shown = ", ".join(_quote(v) for v in values[:_MAX_LISTED_VALUES])
    more = f", … ({len(values) - _MAX_LISTED_VALUES} more)" if len(values) > _MAX_LISTED_VALUES else ""
    return f"any of {shown}{more}"


def describe_criterion(c: Criterion) -> str:
    if c.field is None:
        return f"any field contains {_values_phrase(c.values)}"
    if c.value_type == "null":
        return f"{c.field} is empty"
    if "exists" in c.modifiers:
        return f"{c.field} {'exists' if c.values[0] in ('true', 'exists') else 'does not exist'}"
    verbs = [_MODIFIER_PHRASES[m] for m in c.modifiers if m in _MODIFIER_PHRASES and m not in ("all", "cased", "wide", "utf16", "utf16be")]
    verb = " ".join(verbs) if verbs else ("matches regex" if c.value_type == "regex" else "equals")
    suffix = " (case-sensitive)" if "cased" in c.modifiers else ""
    return f"{c.field} {verb} {_values_phrase(c.values)}{suffix}"


def _collapse_same_field(node: Boolean) -> Criterion | None:
    """A value-list expansion (OR of the same field/modifiers) reads better as one line."""
    if node.op != "or":
        return None
    leaves = node.children
    if not all(isinstance(c, Criterion) for c in leaves):
        return None
    first = leaves[0]
    assert isinstance(first, Criterion)
    if any(c.field != first.field or c.modifiers != first.modifiers or c.selection != first.selection for c in leaves if isinstance(c, Criterion)):  # noqa: E501
        return None
    values = tuple(v for c in leaves if isinstance(c, Criterion) for v in c.values)
    return Criterion(first.selection, first.field, first.modifiers, values, first.value_type, first.tier, first.category, first.confidence, first.note, first.routing)


def _outline(node: Node, depth: int, out: list[OutlineLine], role: str | None = None) -> None:
    if isinstance(node, Criterion):
        out.append(OutlineLine(depth, describe_criterion(node), role or "criterion", node.selection))
        return
    collapsed = _collapse_same_field(node)
    if collapsed is not None:
        out.append(OutlineLine(depth, describe_criterion(collapsed), role or "criterion", collapsed.selection))
        return
    if node.op == "not":
        head = "excluding events where" if role == "filter" else "NOT (events where)"
        # A NOT wraps its selection's expansion; report the wrapped selection's name so filters are attributable.
        inner = node.children[0] if len(node.children) == 1 else None
        selection = node.selection or (inner.selection if isinstance(inner, Boolean) else inner.selection if isinstance(inner, Criterion) else None)
        out.append(OutlineLine(depth, head + (f" [{selection}]" if selection else ""), role or "not", selection))
        for c in node.children:
            _outline(c, depth + 1, out)
        return
    head = "all of the following" if node.op == "and" else "any of the following"
    if node.selection:
        head += f" [{node.selection}]"
    out.append(OutlineLine(depth, head, role or node.op, node.selection))
    for c in node.children:
        _outline(c, depth + 1, out, "filter" if node.op == "and" and is_filter(c, node.children) else None)


def _summary(ir: RuleIR, filters: int) -> str:
    root = ir.root
    criteria = list(iter_criteria(root))
    fields = sorted({c.field for c in criteria if c.field})
    field_text = ", ".join(fields[:5]) + (" and others" if len(fields) > 5 else "") if fields else "keyword matches"
    if isinstance(root, Boolean) and root.op == "not":
        shape = "fires on every event that does NOT match the listed indicators"
    elif isinstance(root, Boolean) and root.op == "and":
        positives = sum(1 for c in root.children if not is_filter(c, root.children))
        shape = f"requires {positives} condition group(s) to all hold"
        if filters:
            shape += f", minus {filters} exclusion filter(s)"
    elif isinstance(root, Boolean) and root.op == "or":
        shape = f"fires when any of {len(root.children)} alternatives holds"
    else:
        shape = "fires on a single field test"
    return f"Matches {logsource_text(ir)} and {shape}, testing {field_text}."


def describe(ir: RuleIR) -> ScopeResult:
    outline: list[OutlineLine] = []
    _outline(ir.root, 0, outline)
    filters = sum(1 for line in outline if line.role == "filter")
    criteria = list(iter_criteria(ir.root))
    fields = tuple(sorted({c.field for c in criteria if c.field}))
    selections = []
    for name in ir.selections:
        sel_criteria = [c for c in criteria if c.selection == name]
        selections.append({
            "name": name,
            "role": "filter" if any(line.selection == name and line.role == "filter" for line in outline) else "primary",
            "criteria": len(sel_criteria),
        })
    return ScopeResult(
        summary=_summary(ir, filters),
        logsource_text=logsource_text(ir),
        outline=tuple(outline),
        fields=fields,
        selections=tuple(selections),
        criteria_count=len(criteria),
        filter_count=filters,
    )
