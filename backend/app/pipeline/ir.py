"""Normalized intermediate representation of a parsed Sigma rule.

Built once from pySigma's fully resolved condition tree (never from the raw
``detection`` dict, which would lose intra-selection AND/OR structure), then
walked by every downstream card: parsed structure, scope & match, Pyramid of Pain,
lint, ATT&CK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

BooleanOp = Literal["and", "or", "not"]

# Pyramid of Pain tiers, low (cheap to evade) to high (expensive to evade).
TIER_HASH = 1
TIER_IP = 2
TIER_DOMAIN = 3
TIER_ARTIFACT = 4
TIER_TOOL = 5
TIER_TTP = 6

TIER_NAMES: dict[int, str] = {
    TIER_HASH: "Hash values",
    TIER_IP: "IP addresses",
    TIER_DOMAIN: "Domain names",
    TIER_ARTIFACT: "Host/network artifacts",
    TIER_TOOL: "Tools",
    TIER_TTP: "TTPs",
}

Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class Criterion:
    """A single field/value test: one leaf of the condition tree."""

    selection: str
    field: str | None  # None means a keyword search across the whole event
    modifiers: tuple[str, ...]
    values: tuple[str, ...]  # original (pre-modifier) values, as display strings
    value_type: str  # string | number | bool | null | regex | cidr | fieldref | expansion | query | exists | other
    tier: int
    category: str  # hash | ip | domain | host_artifact | behavioral | tool | relational | keyword
    confidence: Confidence = "high"
    note: str | None = None  # taxonomy annotation, e.g. "recognized tool: mimikatz"
    routing: bool = False  # field is fixed by the log source, not attacker-controllable
    outcome: bool = False  # field records the outcome/status of an action, not the action itself

    @property
    def kind(self) -> str:
        return "criterion"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "criterion",
            "selection": self.selection,
            "field": self.field,
            "modifiers": list(self.modifiers),
            "values": list(self.values),
            "value_type": self.value_type,
            "tier": self.tier,
            "tier_name": TIER_NAMES[self.tier],
            "category": self.category,
            "confidence": self.confidence,
            "note": self.note,
            "routing": self.routing,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class Boolean:
    op: BooleanOp
    children: tuple[Node, ...]
    selection: str | None = None  # set when this node is the expansion of a named selection

    @property
    def kind(self) -> str:
        return "boolean"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "boolean",
            "op": self.op,
            "selection": self.selection,
            "children": [c.to_dict() for c in self.children],
        }


Node = Criterion | Boolean


@dataclass(frozen=True)
class LogSource:
    category: str | None = None
    product: str | None = None
    service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "product": self.product, "service": self.service}


@dataclass(frozen=True)
class Metadata:
    """Author-declared fields, read from the raw YAML (so a rule pySigma partly rejects still carries them)."""

    title: str | None = None
    id: str | None = None
    status: str | None = None
    level: str | None = None
    description: str | None = None
    author: str | None = None
    date: str | None = None
    modified: str | None = None
    references: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    logsource: LogSource = field(default_factory=LogSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "level": self.level,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "modified": self.modified,
            "references": list(self.references),
            "falsepositives": list(self.falsepositives),
            "tags": list(self.tags),
            "logsource": self.logsource.to_dict(),
        }


@dataclass(frozen=True)
class RuleIR:
    metadata: Metadata
    condition: str
    root: Node
    selections: tuple[str, ...]  # selection names in the order they appear in the resolved tree

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "condition": self.condition,
            "selections": list(self.selections),
            "root": self.root.to_dict(),
        }


def iter_criteria(node: Node):
    """Depth-first iteration over every leaf criterion under ``node``."""
    if isinstance(node, Criterion):
        yield node
    else:
        for child in node.children:
            yield from iter_criteria(child)
