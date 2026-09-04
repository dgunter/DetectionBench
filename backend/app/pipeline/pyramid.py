"""Pyramid of Pain classification: boolean resolution over the IR.

Applied in this order (build spec, locked):
1. every leaf criterion already carries its taxonomy tier;
2. a NOT branch AND-ed alongside a non-negated branch is an exclusion filter
   and is excluded from tier scoring; a bare NOT is primary logic;
3. AND -> min tier of the remaining branches (attacker breaks the cheapest);
4. OR -> max tier of the alternatives (attacker must defeat every branch);
5. TTP escalation, last and only on AND nodes: promote to tier 6 only when
   every non-filter branch is already >= tier 4 and the branches span >= 2
   distinct categories. It can never override the min rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.pipeline.ir import (
    TIER_ARTIFACT,
    TIER_DOMAIN,
    TIER_NAMES,
    TIER_TTP,
    Boolean,
    Confidence,
    Criterion,
    Metadata,
    Node,
    RuleIR,
    iter_criteria,
)

_CONF_RANK: dict[str, int] = {"high": 3, "medium": 2, "low": 1}


def _weakest(*confidences: Confidence) -> Confidence:
    return min(confidences, key=lambda c: _CONF_RANK[c]) if confidences else "high"


@dataclass(frozen=True)
class Resolution:
    tier: int
    confidence: Confidence
    categories: frozenset[str]
    label: str  # short human description of what set this tier
    steps: tuple[str, ...] = ()  # rationale trace, top-down


@dataclass(frozen=True)
class Advisory:
    kind: str  # filter | routing | level_vs_tier | bare_not
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "message": self.message, "detail": self.detail}


@dataclass(frozen=True)
class PyramidResult:
    tier: int
    confidence: Confidence
    rationale: str
    steps: tuple[str, ...]
    categories: tuple[str, ...]
    advisories: tuple[Advisory, ...]
    provenance: str = "deterministic:static"

    @property
    def value(self) -> str:
        return TIER_NAMES[self.tier]

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "tier": self.tier,
            "tier_name": self.value,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "rationale": self.rationale,
            "steps": list(self.steps),
            "categories": list(self.categories),
            "advisories": [a.to_dict() for a in self.advisories],
        }


def _describe(node: Node) -> str:
    if isinstance(node, Criterion):
        return f"`{node.field}`" if node.field else "keyword search"
    if node.selection:
        return f"`{node.selection}`"
    return f"{node.op.upper()} group"


def _tier_label(tier: int) -> str:
    return f"tier {tier} ({TIER_NAMES[tier]})"


def _is_not(node: Node) -> bool:
    return isinstance(node, Boolean) and node.op == "not"


def _context_only(node: Node) -> bool:
    """True when every leaf under ``node`` is a routing or outcome/status field: log-source context, not an indicator."""
    leaves = list(iter_criteria(node))
    return bool(leaves) and all(leaf.routing or leaf.outcome for leaf in leaves)


def is_filter(child: Node, siblings: tuple[Node, ...]) -> bool:
    """A NOT is an exclusion filter when a non-negated sibling exists under the same AND.

    Exception (allowlist in disguise): when every non-negated sibling is routing/outcome
    context only (``EventID: 4688 and not filter_known_images``), the negations are the
    rule's real logic, so none of them is a filter; each resolves as a bare NOT and the
    usual AND-min applies (the same treatment as an all-negated AND).
    """
    if not _is_not(child):
        return False
    positives = [s for s in siblings if not _is_not(s)]
    return bool(positives) and not all(_context_only(p) for p in positives)


def negations_are_primary(node: Boolean) -> bool:
    """An AND with >= 1 NOT whose positive branches are all routing/outcome context."""
    if node.op != "and":
        return False
    positives = [c for c in node.children if not _is_not(c)]
    return any(_is_not(c) for c in node.children) and bool(positives) and all(_context_only(p) for p in positives)


def resolve(node: Node) -> Resolution:
    if isinstance(node, Criterion):
        label = f"{_describe(node)} is {node.category.replace('_', ' ')}"
        return Resolution(node.tier, node.confidence, frozenset({node.category}), label, (f"{_describe(node)} -> {_tier_label(node.tier)}",))

    if node.op == "not":
        inner = resolve(node.children[0]) if len(node.children) == 1 else _resolve_or(node.children)
        return Resolution(
            inner.tier,
            _weakest(inner.confidence, "medium"),
            inner.categories,
            f"negated {inner.label}",
            (f"bare NOT over {_describe(node.children[0])}: negated indicator list behaves as an allowlist; scored at the indicator's {_tier_label(inner.tier)}, durability likely understated",) + inner.steps,
        )

    if node.op == "or":
        return _resolve_or(node.children, node)

    return _resolve_and(node)


def _resolve_or(children: tuple[Node, ...], node: Boolean | None = None) -> Resolution:
    resolved = [resolve(c) for c in children]
    top = max(r.tier for r in resolved)
    winners = [r for r in resolved if r.tier == top]
    categories = frozenset().union(*(r.categories for r in winners))
    confidence = _weakest(*(r.confidence for r in winners))
    name = _describe(node) if node else "OR group"
    steps = (f"{name}: OR -> max of {len(resolved)} alternatives = {_tier_label(top)} (attacker must defeat every alternative; the hardest is the bottleneck)",)
    return Resolution(top, confidence, categories, winners[0].label, steps + winners[0].steps)


def _resolve_and(node: Boolean) -> Resolution:
    positives = [c for c in node.children if not is_filter(c, node.children)]
    filters = [c for c in node.children if is_filter(c, node.children)]
    resolved = [resolve(c) for c in positives]
    floor = min(r.tier for r in resolved)
    bottleneck = [r for r in resolved if r.tier == floor]
    confidence = _weakest(*(r.confidence for r in bottleneck))
    categories = frozenset().union(*(r.categories for r in resolved))
    name = _describe(node)
    steps = [f"{name}: AND -> min of {len(resolved)} required branch(es) = {_tier_label(floor)} (attacker only needs to break the cheapest required condition)"]
    if negations_are_primary(node):
        context = ", ".join(_describe(c) for c in positives if not _is_not(c))
        steps.insert(0, f"{name}: the non-negated branch(es) ({context}) are routing/outcome context only, so the negation(s) are the primary logic, not exclusion filters: a negated list behaves as an allowlist; scored at the negated indicators' tier, confidence medium, durability likely understated")
    if filters:
        steps.append(f"{len(filters)} exclusion filter(s) excluded from scoring: " + ", ".join(_filter_name(f) for f in filters))

    # TTP escalation, applied last, only here, never overriding the min rule.
    # Branches made only of routing fields (Channel, Provider_Name, ...), outcome/status fields
    # (errorCode, result, ...) or field-less keywords still floor the tier in v1 but are not
    # behavioral evidence, so they don't count toward the "spans >= 2 categories" test.
    evidence = [r for c, r in zip(positives, resolved, strict=True) if not _non_evidence(c)]
    if len(resolved) >= 2 and floor >= TIER_ARTIFACT:
        distinct = frozenset().union(*(r.categories for r in evidence)) if evidence else frozenset()
        if len(evidence) >= 2 and len(distinct) >= 2:
            steps.append(f"TTP escalation: every required branch is >= tier 4 and the branches span {len(distinct)} categories ({', '.join(sorted(distinct))}) -> promoted to {_tier_label(TIER_TTP)}, confidence medium (fuzziest tier in Bianco's model)")
            return Resolution(TIER_TTP, _weakest(confidence, "medium"), distinct, "behavioral chain across categories", tuple(steps))
        if len(evidence) < len(resolved):
            steps.append("no TTP escalation: routing, outcome/status and keyword-only branches are not behavioral evidence and don't count toward the category span")
        else:
            steps.append(f"no TTP escalation: required branches all share one category ({', '.join(sorted(distinct))})")
    elif len(resolved) >= 2 and floor < TIER_ARTIFACT:
        steps.append(f"no TTP escalation: a required branch is floored at {_tier_label(floor)}")

    return Resolution(floor, confidence, categories, bottleneck[0].label, tuple(steps) + bottleneck[0].steps)


def _non_evidence(node: Node) -> bool:
    """True when every leaf under ``node`` is routing, outcome/status, or a field-less keyword."""
    leaves = list(iter_criteria(node))
    return bool(leaves) and all(leaf.routing or leaf.outcome or leaf.field is None for leaf in leaves)


def _filter_name(node: Node) -> str:
    inner = node.children[0] if isinstance(node, Boolean) and node.op == "not" and node.children else node
    if isinstance(inner, Boolean) and inner.selection:
        return f"`{inner.selection}`"
    if isinstance(inner, Criterion):
        return f"`{inner.selection}`"
    return "NOT group"


# ---------------------------------------------------------------------------
# Advisories (never change the tier)
# ---------------------------------------------------------------------------


def _collect_filters(node: Node, out: list[tuple[str, Resolution]]) -> None:
    if isinstance(node, Criterion):
        return
    if node.op == "and":
        for c in node.children:
            if is_filter(c, node.children):
                out.append((_filter_name(c), resolve(c.children[0]) if len(c.children) == 1 else _resolve_or(c.children)))
    for c in node.children:
        _collect_filters(c, out)


def _collect_allowlist_ands(node: Node, out: list[str]) -> None:
    if isinstance(node, Criterion):
        return
    if negations_are_primary(node):
        out.append(_describe(node))
    for c in node.children:
        _collect_allowlist_ands(c, out)


def _collect_routing(node: Node, out: list[str]) -> None:
    if isinstance(node, Criterion):
        return
    if node.op == "and":
        for c in node.children:
            if is_filter(c, node.children):
                continue
            leaves = list(iter_criteria(c))
            if leaves and all(leaf.routing for leaf in leaves):
                out.append(_describe(c) if isinstance(c, Boolean) and c.selection else ", ".join(f"`{leaf.field}`" for leaf in leaves))
    for c in node.children:
        _collect_routing(c, out)


def advisories_for(ir: RuleIR, resolution: Resolution) -> tuple[Advisory, ...]:
    out: list[Advisory] = []

    filters: list[tuple[str, Resolution]] = []
    _collect_filters(ir.root, filters)
    if filters:
        cheapest = min(filters, key=lambda f: f[1].tier)
        names = ", ".join(n for n, _ in filters)
        out.append(Advisory(
            "filter",
            f"{len(filters)} exclusion filter(s) ({names}): each exclusion filter is an evasion surface if the attacker can satisfy it. Cheapest filter to satisfy: {cheapest[0]} at {_tier_label(cheapest[1].tier)}. Filters do not change the tier.",
            {"filters": [{"name": n, "tier": r.tier, "tier_name": TIER_NAMES[r.tier]} for n, r in filters], "cheapest": cheapest[0]},
        ))

    routing: list[str] = []
    _collect_routing(ir.root, routing)
    for branch in routing:
        out.append(Advisory(
            "routing",
            f"AND'd branch {branch} is a routing field fixed by the log source, not an evasion point; treat the computed floor as conservative.",
            {"branch": branch},
        ))

    root = ir.root
    if isinstance(root, Boolean) and root.op == "not":
        out.append(Advisory(
            "bare_not",
            "The whole rule is a negation: the negated indicator list behaves as an allowlist, so its durability is likely understated by the indicator tier.",
        ))
    allowlists: list[str] = []
    _collect_allowlist_ands(ir.root, allowlists)
    for branch in allowlists:
        out.append(Advisory(
            "bare_not",
            f"{branch}: its non-negated branches are routing/outcome context only, so the negations are the primary logic (an allowlist in disguise); durability is likely understated by the indicator tier.",
            {"branch": branch},
        ))

    level = (ir.metadata.level or "").lower()
    if level in {"high", "critical"} and resolution.tier <= TIER_DOMAIN:
        out.append(Advisory(
            "level_vs_tier",
            f"Sigma level is `{level}` but the durability tier is {_tier_label(resolution.tier)}: high-impact, low-durability, worth hardening. Severity and durability are separate axes; this is not a disagreement.",
            {"level": level, "tier": resolution.tier},
        ))
    return tuple(out)


def classify(ir: RuleIR) -> PyramidResult:
    resolution = resolve(ir.root)
    advisories = advisories_for(ir, resolution)
    rationale = f"{TIER_NAMES[resolution.tier]} (tier {resolution.tier}): {resolution.label}. " + resolution.steps[0] if resolution.steps else TIER_NAMES[resolution.tier]
    return PyramidResult(
        tier=resolution.tier,
        confidence=resolution.confidence,
        rationale=rationale,
        steps=resolution.steps,
        categories=tuple(sorted(resolution.categories)),
        advisories=advisories,
    )
