"""Offline MITRE ATT&CK lookup backed by the bundled slim dataset."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

RESOURCE_PATH = Path(__file__).resolve().parent.parent / "resources" / "attack" / "enterprise-attack-slim.json"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    is_subtechnique: bool
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    url: str
    revoked: bool = False
    deprecated: bool = False
    revoked_by: str | None = None

    @property
    def retired(self) -> bool:
        return self.revoked or self.deprecated


@dataclass(frozen=True)
class AttackDataset:
    version: str
    tactics: frozenset[str]
    techniques: dict[str, Technique] = field(default_factory=dict)

    @property
    def technique_count(self) -> int:
        return sum(1 for t in self.techniques.values() if not t.retired)

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.upper())


@lru_cache(maxsize=1)
def load_attack_dataset(path: Path = RESOURCE_PATH) -> AttackDataset:
    with path.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    techniques = {
        t["id"].upper(): Technique(
            id=t["id"],
            name=t["name"],
            is_subtechnique=bool(t.get("is_subtechnique")),
            tactics=tuple(t.get("tactics", [])),
            platforms=tuple(t.get("platforms", [])),
            url=t.get("url", ""),
            revoked=bool(t.get("revoked")),
            deprecated=bool(t.get("deprecated")),
            revoked_by=t.get("revoked_by"),
        )
        for t in raw["techniques"]
    }
    return AttackDataset(version=str(raw["attack_version"]), tactics=frozenset(raw["tactics"]), techniques=techniques)
