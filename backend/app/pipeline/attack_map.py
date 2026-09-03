"""ATT&CK mapping: resolve the technique and tactic tags a rule declares
against the bundled offline dataset.

Everything here is ``deterministic:metadata``: it reads what the author
wrote and checks it, it never infers. The findings list feeds the lint card
so technique/tactic problems are reported once, from one place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

from app.pipeline.attack import AttackDataset, Technique

Severity = Literal["error", "warning", "info"]

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
SOFTWARE_TAG = re.compile(r"^attack\.(s\d{4})$", re.IGNORECASE)
GROUP_TAG = re.compile(r"^attack\.(g\d{4})$", re.IGNORECASE)
TACTIC_TAG = re.compile(r"^attack\.([a-z][a-z_-]*)$", re.IGNORECASE)

# ATT&CK v19 renamed one tactic; older rules still carry the old name.
RENAMED_TACTICS = {"defense-evasion": "stealth"}


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    message: str
    tag: str | None = None
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "message": self.message,
            "tag": self.tag,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class TechniqueRef:
    tag: str
    id: str
    status: Literal["valid", "retired", "unknown"]
    name: str | None = None
    url: str | None = None
    tactics: tuple[str, ...] = ()
    is_subtechnique: bool = False
    replaced_by: str | None = None
    replaced_by_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "id": self.id,
            "status": self.status,
            "name": self.name,
            "url": self.url,
            "tactics": list(self.tactics),
            "is_subtechnique": self.is_subtechnique,
            "replaced_by": self.replaced_by,
            "replaced_by_name": self.replaced_by_name,
        }


@dataclass(frozen=True)
class TacticRef:
    tag: str
    name: str
    status: Literal["valid", "renamed", "unknown"]
    renamed_to: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"tag": self.tag, "name": self.name, "status": self.status, "renamed_to": self.renamed_to}


@dataclass(frozen=True)
class AttackMapping:
    dataset_version: str
    techniques: tuple[TechniqueRef, ...] = ()
    tactics: tuple[TacticRef, ...] = ()
    unvalidated: tuple[str, ...] = ()  # attack.s* / attack.g* — legitimate, not checked in v1
    other_tags: tuple[str, ...] = ()  # non-ATT&CK namespaces (cve.*, car.*, detection.*, tlp.*)
    findings: tuple[Finding, ...] = ()
    provenance: str = "deterministic:metadata"
    confidence: str = "high"

    @property
    def declared_count(self) -> int:
        return len(self.techniques) + len(self.tactics) + len(self.unvalidated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_version": self.dataset_version,
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics": [t.to_dict() for t in self.tactics],
            "unvalidated": list(self.unvalidated),
            "other_tags": list(self.other_tags),
            "findings": [f.to_dict() for f in self.findings],
            "provenance": self.provenance,
            "confidence": self.confidence,
            "declared_count": self.declared_count,
        }


def _technique_ref(tag: str, technique_id: str, dataset: AttackDataset) -> tuple[TechniqueRef, Finding | None]:
    technique: Technique | None = dataset.get(technique_id)
    if technique is None:
        return (
            TechniqueRef(tag=tag, id=technique_id, status="unknown"),
            Finding("attack_technique_unknown", "error", f"{technique_id} is not an ATT&CK Enterprise technique (dataset v{dataset.version})", tag),
        )
    if technique.retired:
        replacement = dataset.get(technique.revoked_by) if technique.revoked_by else None
        if technique.revoked_by:
            message = f"{technique_id} ({technique.name}) is retired, replaced by {technique.revoked_by}"
            if replacement:
                message += f" ({replacement.name})"
        else:
            message = f"{technique_id} ({technique.name}) is deprecated with no replacement"
        return (
            TechniqueRef(
                tag=tag,
                id=technique.id,
                status="retired",
                name=technique.name,
                url=technique.url,
                tactics=technique.tactics,
                is_subtechnique=technique.is_subtechnique,
                replaced_by=technique.revoked_by,
                replaced_by_name=replacement.name if replacement else None,
            ),
            Finding("attack_technique_retired", "warning", message, tag),
        )
    return (
        TechniqueRef(
            tag=tag,
            id=technique.id,
            status="valid",
            name=technique.name,
            url=technique.url,
            tactics=technique.tactics,
            is_subtechnique=technique.is_subtechnique,
        ),
        None,
    )


def _tactic_ref(tag: str, raw_name: str, dataset: AttackDataset) -> tuple[TacticRef, Finding | None]:
    name = raw_name.lower().replace("_", "-")
    if name in dataset.tactics:
        return TacticRef(tag=tag, name=name, status="valid"), None
    renamed = RENAMED_TACTICS.get(name)
    if renamed and renamed in dataset.tactics:
        return (
            TacticRef(tag=tag, name=name, status="renamed", renamed_to=renamed),
            Finding("attack_tactic_renamed", "warning", f"tactic '{name}' was renamed '{renamed}' in ATT&CK v19", tag),
        )
    return (
        TacticRef(tag=tag, name=name, status="unknown"),
        Finding("attack_tactic_unknown", "error", f"'{name}' is not an ATT&CK Enterprise tactic (dataset v{dataset.version})", tag),
    )


def map_attack_tags(tags: Iterable[str], dataset: AttackDataset) -> AttackMapping:
    techniques: list[TechniqueRef] = []
    tactics: list[TacticRef] = []
    unvalidated: list[str] = []
    other: list[str] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    for raw in tags:
        tag = str(raw).strip()
        if not tag:
            continue
        key = tag.lower()
        if key in seen:
            findings.append(Finding("attack_tag_duplicate", "info", f"tag '{tag}' is declared more than once", tag))
            continue
        seen.add(key)

        if m := TECHNIQUE_TAG.match(tag):
            ref, finding = _technique_ref(tag, m.group(1).upper(), dataset)
            techniques.append(ref)
            if finding:
                findings.append(finding)
        elif SOFTWARE_TAG.match(tag) or GROUP_TAG.match(tag):
            unvalidated.append(tag)
            kind = "software" if SOFTWARE_TAG.match(tag) else "group"
            findings.append(Finding("attack_software_group_tag", "info", f"{kind} tag '{tag}' is not validated in v1", tag))
        elif m := TACTIC_TAG.match(tag):
            ref, finding = _tactic_ref(tag, m.group(1), dataset)
            tactics.append(ref)
            if finding:
                findings.append(finding)
        elif key.startswith("attack."):
            findings.append(Finding("attack_tag_malformed", "error", f"'{tag}' is not a recognizable ATT&CK technique, tactic, software, or group tag", tag))
        else:
            other.append(tag)

    return AttackMapping(
        dataset_version=dataset.version,
        techniques=tuple(techniques),
        tactics=tuple(tactics),
        unvalidated=tuple(unvalidated),
        other_tags=tuple(other),
        findings=tuple(findings),
    )
