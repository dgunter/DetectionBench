"""Lint table: one bad-metadata fixture exercises every row, plus the clean path and the pySigma merge."""

from __future__ import annotations

from pathlib import Path

from app.pipeline.attack import load_attack_dataset
from app.pipeline.lint import CHECK_TABLE, lint_rule
from app.pipeline.parse import parse_rule

FIXTURES = Path(__file__).parent / "fixtures"
DS = load_attack_dataset()


def _lint(text: str):
    parsed = parse_rule(text)
    return lint_rule(parsed.raw, parsed.ir, list(parsed.rule.detection.detections), parsed.metadata_errors, DS)


def test_every_table_row_is_reported_once_for_the_bad_fixture() -> None:
    result = _lint((FIXTURES / "lint" / "bad_metadata.yml").read_text(encoding="utf-8"))
    by_check = {c.check: c for c in result.checks}
    assert [c.check for c in result.checks] == [c for c, _ in CHECK_TABLE]
    assert by_check["id"].status == "error"
    assert by_check["status"].status == "warning"
    assert by_check["description"].status == "warning"  # "Bad" == title and < 20 chars
    assert by_check["references"].status == "warning"
    assert by_check["level"].status == "error"
    assert by_check["falsepositives"].status == "warning"
    assert by_check["logsource"].status == "warning"  # service only
    assert by_check["selections"].status == "warning"
    assert "unused_selection" in (by_check["selections"].message or "")
    assert by_check["attack_coverage"].status == "pass"  # techniques are declared, even if some are bad
    assert by_check["attack_techniques"].status == "error"  # t9999 unknown outranks t1562.002 retired
    assert by_check["attack_tactics"].status == "error"  # not-a-tactic outranks the defense-evasion rename
    assert by_check["attack_software_groups"].status == "info"
    assert by_check["date"].status == "warning"  # pySigma SigmaDateError mapped onto the table
    assert by_check["title"].status == "pass"

    checks = [f.check for f in result.findings]
    # No double-reporting: pySigma's id/status/level errors are absorbed by the raw-dict rows.
    assert checks.count("id") == 1
    assert checks.count("status") == 1
    assert checks.count("level") == 1
    assert "attack_technique_retired" in checks
    assert "attack_technique_unknown" in checks
    assert "attack_tactic_renamed" in checks
    assert "attack_tactic_unknown" in checks
    assert checks.count("attack_software_group_tag") == 2
    retired = next(f for f in result.findings if f.check == "attack_technique_retired")
    assert "replaced by T1685.001" in retired.message
    assert all(f.confidence == "high" for f in result.findings)
    assert result.count("error") >= 4
    assert result.value.startswith(f"{result.count('error')} errors")


def test_clean_rule_passes_every_row() -> None:
    result = _lint((FIXTURES / "domain_dns_xmr_mining.yml").read_text(encoding="utf-8"))
    assert all(c.status == "pass" for c in result.checks), [c for c in result.checks if c.status != "pass"]
    assert result.findings == ()
    assert result.value == "clean"
    d = result.to_dict()
    assert d["provenance"] == "deterministic:metadata"
    assert d["passed"] == len(CHECK_TABLE)


def test_missing_fields_are_reported_not_crashed() -> None:
    result = _lint("title: t\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\n")
    by_check = {c.check: c for c in result.checks}
    assert by_check["id"].status == "error"
    assert "missing" in (by_check["id"].message or "")
    assert by_check["level"].status == "error"
    assert by_check["status"].status == "warning"
    assert by_check["description"].status == "warning"
    assert by_check["falsepositives"].status == "warning"
    assert by_check["logsource"].status == "pass"
    assert by_check["attack_coverage"].status == "warning"  # no tags at all


def test_pysigma_only_errors_fall_back_to_a_generic_row() -> None:
    # 'related' with a bad type is a pySigma-only check; it must land as a warning, not vanish.
    text = "title: t\nid: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab\nrelated:\n  - id: x\n    type: bogus\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\nlevel: low\n"
    result = _lint(text)
    assert any(f.check == "pysigma" and f.severity == "warning" for f in result.findings)


def test_falsepositives_unknown_only_is_flagged_but_real_notes_pass() -> None:
    base = "title: t\nid: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab\nstatus: test\ndescription: Detects something specific enough\nreferences: [https://example.test]\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\nlevel: low\n"
    assert {c.check: c.status for c in _lint(base + "falsepositives:\n  - Unknown\n").checks}["falsepositives"] == "warning"
    assert {c.check: c.status for c in _lint(base + "falsepositives:\n  - Admin scripts\n").checks}["falsepositives"] == "pass"


def test_tactic_only_rule_warns_on_technique_coverage() -> None:
    base = "title: t\nid: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab\nstatus: test\ndescription: Detects something specific enough\nreferences: [https://example.test]\nfalsepositives: [Admin scripts]\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\nlevel: low\n"
    tactic_only = _lint(base + "tags:\n  - attack.execution\n")
    rows = {c.check: c.status for c in tactic_only.checks}
    assert rows["attack_coverage"] == "warning"
    assert rows["attack_tactics"] == "pass"
    assert [f.check for f in tactic_only.findings] == ["attack_coverage"]
    with_technique = _lint(base + "tags:\n  - attack.execution\n  - attack.t1059.001\n")
    assert {c.check: c.status for c in with_technique.checks}["attack_coverage"] == "pass"
    assert with_technique.findings == ()
