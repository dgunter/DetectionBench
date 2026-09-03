"""Golden fixtures: the demo rules run through the real pipeline.

Each ``<name>.yml`` has a ``<name>.expected.json`` with one section per
pipeline stage. A section is only checked when present, so later stages
(lint, ATT&CK) add their sections without touching the earlier ones.
The tier/confidence table below is written by hand from the build spec so
the golden values are anchored to the methodology, not just pinned output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.pipeline.ir import iter_criteria
from app.pipeline.parse import parse_rule
from app.pipeline.pyramid import classify
from app.pipeline.scope import describe

FIXTURES = Path(__file__).parent / "fixtures"
RULES = sorted(FIXTURES.glob("*.yml"))

# Hand-written from the spec: (tier, confidence) per demo rule.
SPEC_TIERS = {
    "hash_imphash_sharpevtmute": (1, "high"),
    "ip_bare_not_zeek_rdp": (2, "medium"),
    "artifact_sysnative_filters": (4, "high"),
    "relational_fieldref_delete_own_image": (4, "medium"),
    "domain_dns_xmr_mining": (3, "high"),
    "tool_rubeus_pe_metadata": (5, "medium"),
    "ttp_dump64_renamed_procdump": (6, "medium"),
}


def _actual(rule_path: Path) -> dict:
    parsed = parse_rule(rule_path.read_text(encoding="utf-8"))
    ir = parsed.ir
    pyramid = classify(ir)
    scope = describe(ir)
    return {
        "parse": {
            "condition": ir.condition,
            "selections": list(ir.selections),
            "root_kind": ir.root.kind,
            "root_op": getattr(ir.root, "op", None),
            "metadata_errors": sorted(type(e).__name__ for e in parsed.metadata_errors),
            "criteria": [
                {
                    "selection": c.selection,
                    "field": c.field,
                    "modifiers": list(c.modifiers),
                    "value_type": c.value_type,
                    "tier": c.tier,
                    "category": c.category,
                    "confidence": c.confidence,
                }
                for c in iter_criteria(ir.root)
            ],
        },
        "pyramid": {
            "tier": pyramid.tier,
            "value": pyramid.value,
            "confidence": pyramid.confidence,
            "provenance": pyramid.provenance,
            "categories": list(pyramid.categories),
            "advisory_kinds": [a.kind for a in pyramid.advisories],
        },
        "scope": {
            "logsource_text": scope.logsource_text,
            "fields": list(scope.fields),
            "criteria_count": scope.criteria_count,
            "filter_count": scope.filter_count,
            "selections": list(scope.selections),
            "outline": [line.text for line in scope.outline],
        },
    }


@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_golden(rule_path: Path) -> None:
    expected = json.loads(rule_path.with_suffix(".expected.json").read_text(encoding="utf-8"))
    actual = _actual(rule_path)
    for section, want in expected.items():
        assert actual[section] == want, f"{rule_path.stem}: section '{section}' drifted"


@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_golden_tiers_match_spec(rule_path: Path) -> None:
    pyramid = classify(parse_rule(rule_path.read_text(encoding="utf-8")).ir)
    assert (pyramid.tier, pyramid.confidence) == SPEC_TIERS[rule_path.stem]


def test_every_fixture_has_expectations() -> None:
    assert RULES, "no fixtures found"
    for p in RULES:
        assert p.with_suffix(".expected.json").exists(), f"missing expected file for {p.name}"
