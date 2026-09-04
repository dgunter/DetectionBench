"""YAML -> pySigma -> RuleIR.

Entry point is ``SigmaCollection.from_yaml(text, collect_errors=True)``. Metadata
problems (bad id/status/level/date, missing logsource) land in ``rule.errors`` and
are returned for the lint card; anything that leaves the rule without a usable
condition tree is a structured ``ParseError``, never a 500.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.modifiers import reverse_modifier_mapping
from sigma.rule import SigmaRule
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaString,
)

from app.pipeline.ir import Boolean, Criterion, LogSource, Metadata, Node, RuleIR
from app.pipeline.taxonomy import classify_leaf

MAX_RULE_BYTES = 64 * 1024


class ParseError(Exception):
    """Structured parse failure. ``code`` is stable for clients; ``message`` is for humans."""

    def __init__(self, code: str, message: str, detail: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "detail": self.detail}


@dataclass(frozen=True)
class ParsedRule:
    ir: RuleIR
    raw: dict[str, Any]  # raw YAML mapping, for metadata lint
    rule: SigmaRule
    metadata_errors: tuple[SigmaError, ...] = field(default_factory=tuple)  # non-fatal pySigma errors


# ---------------------------------------------------------------------------
# Raw YAML
# ---------------------------------------------------------------------------


def load_raw_documents(text: str) -> list[Any]:
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        raise ParseError("too_large", "rule is larger than 64 KB")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ParseError("invalid_yaml", "the text is not valid YAML", detail=_yaml_error_detail(exc)) from exc
    except ValueError as exc:  # PyYAML raises bare ValueError for impossible timestamps like 2020-13-45
        raise ParseError("invalid_yaml", "the text is not valid YAML", detail=f"invalid value: {exc}") from exc
    if not docs:
        raise ParseError("empty", "no rule found: paste a Sigma rule to classify")
    if len(docs) > 1:
        raise ParseError("multiple_rules", "one rule at a time: the paste contains several YAML documents")
    doc = docs[0]
    if not isinstance(doc, dict):
        raise ParseError("not_a_mapping", "a Sigma rule is a YAML mapping with title, logsource and detection keys")
    if "correlation" in doc:
        raise ParseError("correlation_rule", "correlation rules aren't supported in v1")
    return docs


def _yaml_error_detail(exc: yaml.YAMLError) -> str | None:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    if mark is not None:
        return f"line {mark.line + 1}, column {mark.column + 1}: {problem}"
    return problem


# ---------------------------------------------------------------------------
# Metadata (from the raw dict, so it survives pySigma metadata rejections)
# ---------------------------------------------------------------------------


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip() if not isinstance(value, str) else value.strip()


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        items: list[Any] = []
    elif isinstance(value, (list, tuple)):
        items = [v for v in value if v is not None]
    else:
        items = [value]
    return tuple(str(v) for v in items)


def build_metadata(raw: dict[str, Any]) -> Metadata:
    ls = raw.get("logsource") if isinstance(raw.get("logsource"), dict) else {}
    return Metadata(
        title=_as_str(raw.get("title")),
        id=_as_str(raw.get("id")),
        status=_as_str(raw.get("status")),
        level=_as_str(raw.get("level")),
        description=_as_str(raw.get("description")),
        author=_as_str(raw.get("author")),
        date=_as_str(raw.get("date")),
        modified=_as_str(raw.get("modified")),
        references=_as_str_tuple(raw.get("references")),
        falsepositives=_as_str_tuple(raw.get("falsepositives")),
        tags=_as_str_tuple(raw.get("tags")),
        logsource=LogSource(
            category=_as_str(ls.get("category")),
            product=_as_str(ls.get("product")),
            service=_as_str(ls.get("service")),
        ),
    )


# ---------------------------------------------------------------------------
# Condition tree -> IR
# ---------------------------------------------------------------------------

_FATAL_ERROR_CODES = {
    "SigmaDetectionError": "invalid_detection",
    "SigmaConditionError": "invalid_condition",
    "SigmaModifierError": "invalid_modifier",
    "SigmaTypeError": "invalid_value",
    "SigmaValueError": "invalid_value",
    "SigmaRegularExpressionError": "invalid_regex",
    "SigmaPlaceholderError": "invalid_value",
}


def _display_value(value: Any) -> str:
    if isinstance(value, SigmaCIDRExpression):
        return value.cidr
    if isinstance(value, SigmaFieldReference):
        return value.field
    if isinstance(value, SigmaRegularExpression):
        return str(value.regexp)
    if isinstance(value, SigmaNumber):
        return str(value.number)
    if isinstance(value, SigmaBool):
        return "true" if value.boolean else "false"
    if isinstance(value, SigmaNull):
        return "null"
    if isinstance(value, SigmaExists):
        return "exists"
    if isinstance(value, SigmaQueryExpression):
        return str(value.expr)
    if isinstance(value, SigmaExpansion):
        return ", ".join(_display_value(v) for v in value.values)
    if isinstance(value, SigmaString):
        return str(value)
    return str(value)


def _value_type(value: Any) -> str:
    if isinstance(value, SigmaCIDRExpression):
        return "cidr"
    if isinstance(value, SigmaFieldReference):
        return "fieldref"
    if isinstance(value, SigmaRegularExpression):
        return "regex"
    if isinstance(value, SigmaNumber):
        return "number"
    if isinstance(value, SigmaBool):
        return "bool"
    if isinstance(value, SigmaNull):
        return "null"
    if isinstance(value, SigmaExists):
        return "exists"
    if isinstance(value, SigmaQueryExpression):
        return "query"
    if isinstance(value, SigmaExpansion):
        return "expansion"
    if isinstance(value, SigmaString):
        return "string"
    return "other"


def _index_detection_items(rule: SigmaRule) -> tuple[dict[int, tuple[str, SigmaDetectionItem]], dict[str, list[SigmaDetectionItem]]]:
    """Map each value object back to the detection item (and selection) it came from.

    pySigma builds leaf nodes with the very same value objects held by the
    ``SigmaDetectionItem`` (verified in ``SigmaDetectionItem.postprocess``), so
    identity is a reliable join key and gives us modifiers and original values
    without reconciling against the raw dict.
    """
    by_value: dict[int, tuple[str, SigmaDetectionItem]] = {}
    by_selection: dict[str, list[SigmaDetectionItem]] = {}

    def walk(name: str, det: SigmaDetection | SigmaDetectionItem) -> None:
        if isinstance(det, SigmaDetectionItem):
            by_selection.setdefault(name, []).append(det)
            for v in det.value:
                by_value[id(v)] = (name, det)
            return
        for item in det.detection_items:
            walk(name, item)

    for name, det in rule.detection.detections.items():
        walk(name, det)
    return by_value, by_selection


def _selection_of(node: Any) -> str | None:
    """Name of the nearest enclosing selection, via the ``.parent`` chain."""
    p = getattr(node, "parent", None)
    while p is not None:
        if isinstance(p, ConditionIdentifier):
            return p.identifier
        p = getattr(p, "parent", None)
    return None


def _is_selection_root(node: Any) -> str | None:
    """Selection name if ``node`` is the direct expansion of a named selection."""
    p = getattr(node, "parent", None)
    while p is not None and isinstance(p, (SigmaDetection, SigmaDetectionItem)):
        p = getattr(p, "parent", None)
    if isinstance(p, ConditionIdentifier):
        return p.identifier
    return None


def _modifier_names(item: SigmaDetectionItem | None) -> tuple[str, ...]:
    if item is None:
        return ()
    return tuple(reverse_modifier_mapping.get(m.__name__, m.__name__.lower()) for m in item.modifiers)


def _original_values(item: SigmaDetectionItem | None, fallback: Any) -> tuple[str, ...]:
    if item is not None and item.original_value:
        return tuple(_display_value(v) for v in item.original_value)
    return (_display_value(fallback),)


class _Builder:
    def __init__(self, rule: SigmaRule, logsource: LogSource):
        self.rule = rule
        self.logsource = logsource
        self.by_value, self.by_selection = _index_detection_items(rule)
        self.selections: list[str] = []

    def _note_selection(self, name: str | None) -> None:
        if name and name not in self.selections:
            self.selections.append(name)

    def leaf(self, node: ConditionFieldEqualsValueExpression | ConditionValueExpression) -> Criterion:
        field_name = getattr(node, "field", None)
        value = node.value
        hit = self.by_value.get(id(value))
        selection = hit[0] if hit else (_selection_of(node) or "?")
        item = hit[1] if hit else None
        if item is None and selection in self.by_selection:
            # SigmaNull leaves are minted fresh; recover the item by field name within the selection.
            for cand in self.by_selection[selection]:
                if cand.field == field_name:
                    item = cand
                    break
        self._note_selection(selection)
        modifiers = _modifier_names(item)
        vtype = _value_type(value)
        # A multi-value item is expanded to one leaf per value; keep the leaf's own value, not the whole list.
        if item is not None and len(item.value) > 1:
            values: tuple[str, ...] = (_display_value(_original_for(item, value)),)
        else:
            values = _original_values(item, value)
        cls = classify_leaf(field_name, vtype, values, modifiers, self.logsource)
        return Criterion(
            selection=selection,
            field=field_name,
            modifiers=modifiers,
            values=values,
            value_type=vtype,
            tier=cls.tier,
            category=cls.category,
            confidence=cls.confidence,
            note=cls.note,
            routing=cls.routing,
            outcome=cls.outcome,
        )

    def build(self, node: Any) -> Node:
        if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
            return self.leaf(node)
        if isinstance(node, ConditionItem):
            op = {ConditionAND: "and", ConditionOR: "or", ConditionNOT: "not"}.get(type(node))
            if op is None:
                raise ParseError("unsupported_condition", f"unsupported condition node: {type(node).__name__}")
            selection = _is_selection_root(node)
            self._note_selection(selection)
            children = tuple(self.build(a) for a in node.args if a is not None)
            if not children:
                raise ParseError("invalid_detection", "a selection resolved to no criteria")
            return Boolean(op=op, children=children, selection=selection)
        raise ParseError("unsupported_condition", f"unsupported condition node: {type(node).__name__}")


def _original_for(item: SigmaDetectionItem, value: Any) -> Any:
    """Original (pre-modifier) value corresponding to a modified value in a multi-value item."""
    if item.original_value and len(item.original_value) == len(item.value):
        for orig, mod in zip(item.original_value, item.value, strict=True):
            if mod is value:
                return orig
    return value


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_rule(text: str) -> ParsedRule:
    raw = load_raw_documents(text)[0]
    try:
        collection = SigmaCollection.from_yaml(text, collect_errors=True)
    except SigmaError as exc:
        raise ParseError("sigma_error", "pySigma could not load the rule", detail=str(exc)) from exc
    except (AttributeError, TypeError, ValueError) as exc:  # malformed structure pySigma doesn't guard
        raise ParseError("invalid_rule", "the rule structure could not be interpreted", detail=str(exc)) from exc

    if len(collection.rules) != 1:
        raise ParseError("multiple_rules", "one rule at a time: the paste contains several rules")
    rule = collection.rules[0]
    if not isinstance(rule, SigmaRule):
        raise ParseError("correlation_rule", "correlation rules aren't supported in v1")

    fatal = [e for e in rule.errors if type(e).__name__ in _FATAL_ERROR_CODES]
    metadata_errors = tuple(e for e in rule.errors if type(e).__name__ not in _FATAL_ERROR_CODES)
    if fatal:
        first = fatal[0]
        raise ParseError(_FATAL_ERROR_CODES[type(first).__name__], "the detection section could not be parsed", detail=str(first))

    parsed_conditions = getattr(rule.detection, "parsed_condition", None)
    if not parsed_conditions:
        raise ParseError("invalid_condition", "the rule has no usable condition")

    metadata = build_metadata(raw)
    builder = _Builder(rule, metadata.logsource)
    trees = []
    for pc in parsed_conditions:
        try:
            tree = pc.parse()
        except SigmaError as exc:
            raise ParseError("invalid_condition", "the condition references something that doesn't exist", detail=str(exc)) from exc
        if tree is None:
            raise ParseError("invalid_detection", "the condition resolved to nothing")
        trees.append(builder.build(tree))

    # Multiple conditions (legacy list form) are OR'd together per the Sigma specification.
    root: Node = trees[0] if len(trees) == 1 else Boolean(op="or", children=tuple(trees))
    condition_text = " | ".join(str(pc.condition) for pc in parsed_conditions)

    ir = RuleIR(metadata=metadata, condition=condition_text, root=root, selections=tuple(builder.selections))
    return ParsedRule(ir=ir, raw=raw, rule=rule, metadata_errors=metadata_errors)
