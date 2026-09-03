"""Parsing: YAML -> pySigma -> IR, plus every structured rejection the spec names."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.pipeline.ir import Boolean, Criterion, iter_criteria
from app.pipeline.parse import MAX_RULE_BYTES, ParseError, parse_rule

FIXTURES = Path(__file__).parent / "fixtures"

BASE = """title: t
id: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
status: test
logsource:
  category: process_creation
  product: windows
"""
SIMPLE = BASE + "detection:\n  sel:\n    Image: x\n  condition: sel\nlevel: low\n"


def _parse_error(text: str) -> ParseError:
    with pytest.raises(ParseError) as info:
        parse_rule(text)
    return info.value


@pytest.mark.parametrize(
    ("name", "text", "code"),
    [
        ("empty", "", "empty"),
        ("comment only", "# nothing here\n", "empty"),
        ("scalar", "just a string", "not_a_mapping"),
        ("list", "- a\n- b\n", "not_a_mapping"),
        ("bad yaml", "title: x\n  bad: [unclosed", "invalid_yaml"),
        ("tabs", "title: t\n\tid: x\n", "invalid_yaml"),
        ("multi doc", SIMPLE + "---\n" + SIMPLE.replace("3c1b5fb0", "4c1b5fb0"), "multiple_rules"),
        ("no detection", BASE + "level: low\n", "invalid_detection"),
        ("no condition", BASE + "detection:\n  sel:\n    Image: x\n", "invalid_condition"),
        ("unknown selection", BASE + "detection:\n  sel:\n    Image: x\n  condition: sel and nope\n", "invalid_condition"),
        ("bad modifier", BASE + "detection:\n  sel:\n    Image|bogus: x\n  condition: sel\n", "invalid_modifier"),
        ("empty selection", BASE + "detection:\n  sel: {}\n  condition: sel\n", "invalid_detection"),
        ("nested list value", BASE + "detection:\n  sel:\n    Image: [[a, b]]\n  condition: sel\n", "invalid_value"),
    ],
)
def test_structured_rejections(name: str, text: str, code: str) -> None:
    err = _parse_error(text)
    assert err.code == code, f"{name}: got {err.code} ({err.message} / {err.detail})"
    assert err.to_dict()["message"]


def test_oversize_rejected_before_yaml_parses() -> None:
    padding = "# " + "x" * (MAX_RULE_BYTES)
    err = _parse_error(SIMPLE + padding)
    assert err.code == "too_large"


def test_yaml_error_carries_line_and_column() -> None:
    err = _parse_error("title: x\n  bad: [unclosed")
    assert err.detail and err.detail.startswith("line 2, column")


def test_lone_correlation_rule_rejected() -> None:
    text = """title: corr
id: 5c1b5fb0-c72f-45ba-abd1-4d4c353144ab
correlation:
  type: event_count
  rules: [3c1b5fb0-c72f-45ba-abd1-4d4c353144ab]
  group-by: [User]
  timespan: 5m
  condition: {gte: 10}
"""
    assert _parse_error(text).code == "correlation_rule"


def test_correlation_bundle_rejected_as_multiple_rules() -> None:
    bundle = SIMPLE + "---\ntitle: corr\nid: 5c1b5fb0-c72f-45ba-abd1-4d4c353144ab\ncorrelation:\n  type: event_count\n  rules: [3c1b5fb0-c72f-45ba-abd1-4d4c353144ab]\n  group-by: [User]\n  timespan: 5m\n  condition: {gte: 10}\n"
    assert _parse_error(bundle).code == "multiple_rules"


def test_metadata_errors_are_not_parse_failures() -> None:
    text = """title: bad
id: not-a-uuid
status: bogus
logsource:
    category: process_creation
detection:
    selection:
        Image|contains: 'x'
    condition: selection
level: bogus
"""
    parsed = parse_rule(text)
    names = {type(e).__name__ for e in parsed.metadata_errors}
    assert {"SigmaIdentifierError", "SigmaLevelError", "SigmaStatusError"} <= names
    # The raw metadata still comes through for the lint card.
    assert parsed.ir.metadata.id == "not-a-uuid"
    assert parsed.ir.metadata.level == "bogus"
    assert isinstance(parsed.ir.root, Criterion)


def test_missing_logsource_is_a_metadata_error_not_a_parse_failure() -> None:
    text = "title: t\nid: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab\ndetection:\n  sel:\n    Image: x\n  condition: sel\n"
    parsed = parse_rule(text)
    assert {type(e).__name__ for e in parsed.metadata_errors} == {"SigmaLogsourceError"}
    assert parsed.ir.metadata.logsource.category is None


def test_sysnative_tree_shape_and_selection_names() -> None:
    parsed = parse_rule((FIXTURES / "artifact_sysnative_filters.yml").read_text())
    ir = parsed.ir
    root = ir.root
    assert isinstance(root, Boolean) and root.op == "and"
    assert [c.op for c in root.children if isinstance(c, Boolean)] == ["or", "not", "not"]
    selection, not_ngen, not_xampp = root.children
    assert isinstance(selection, Boolean) and selection.selection == "selection"
    # list-of-maps selection is an OR of its two maps
    assert [c.field for c in selection.children if isinstance(c, Criterion)] == ["CommandLine", "Image"]
    # `1 of filter_main_*` resolved to the concrete selection, which is an AND of its keys
    ngen = not_ngen.children[0]
    assert isinstance(ngen, Boolean) and ngen.op == "and" and ngen.selection == "filter_main_ngen"
    xampp = not_xampp.children[0]
    assert isinstance(xampp, Boolean) and xampp.op == "and" and xampp.selection == "filter_optional_xampp"
    # `contains|all` over three values is an AND of three criteria with both modifiers recovered
    assert [c.modifiers for c in xampp.children if isinstance(c, Criterion)] == [("contains", "all")] * 3
    assert ir.selections == ("selection", "filter_main_ngen", "filter_optional_xampp")
    assert ir.condition == "selection and not 1 of filter_main_* and not 1 of filter_optional_*"


def test_original_values_survive_modifiers() -> None:
    parsed = parse_rule((FIXTURES / "artifact_sysnative_filters.yml").read_text())
    leaves = list(iter_criteria(parsed.ir.root))
    assert leaves[0].values == (":\\Windows\\Sysnative\\",)  # no wildcards leaked into the display value
    ngen_endswith = next(c for c in leaves if c.modifiers == ("endswith",))
    assert ngen_endswith.values == ("\\ngen.exe",)


def test_value_list_expands_to_one_leaf_per_value() -> None:
    parsed = parse_rule((FIXTURES / "domain_dns_xmr_mining.yml").read_text())
    root = parsed.ir.root
    assert isinstance(root, Boolean) and root.op == "or" and root.selection == "selection"
    leaves = list(iter_criteria(root))
    assert len(leaves) == 20
    assert leaves[0].values == ("pool.minexmr.com",)
    assert {c.field for c in leaves} == {"query"}


def test_special_value_types() -> None:
    text = BASE + """detection:
  keywords:
    - 'evil'
    - 'bad'
  sel:
    a|re: 'x.*y'
    c|startswith: 'z'
    d: [1, 2]
    e|base64offset|contains: 'cmd'
    f|windash: '-x'
    g|cidr: 10.0.0.0/8
    h|fieldref: Image
    i: null
    j: true
  condition: keywords and sel
level: low
"""
    parsed = parse_rule(text)
    by_field = {c.field: c for c in iter_criteria(parsed.ir.root)}
    assert by_field[None].value_type == "string" and by_field[None].category == "keyword"
    assert by_field["a"].value_type == "regex" and by_field["a"].modifiers == ("re",)
    assert by_field["d"].value_type == "number"
    assert by_field["e"].value_type == "expansion" and by_field["e"].values == ("cmd",)
    assert by_field["f"].value_type == "expansion" and by_field["f"].values == ("-x",)
    assert by_field["g"].value_type == "cidr" and by_field["g"].values == ("10.0.0.0/8",)
    assert by_field["h"].value_type == "fieldref" and by_field["h"].values == ("Image",)
    assert by_field["i"].value_type == "null" and by_field["i"].values == ("null",)
    assert by_field["j"].value_type == "bool" and by_field["j"].values == ("true",)


def test_legacy_condition_list_is_ored() -> None:
    text = BASE + "detection:\n  a:\n    Image: x\n  b:\n    CommandLine: y\n  condition:\n    - a\n    - b\nlevel: low\n"
    parsed = parse_rule(text)
    assert isinstance(parsed.ir.root, Boolean) and parsed.ir.root.op == "or"
    assert parsed.ir.condition == "a | b"


def test_ir_serializes_to_plain_json_types() -> None:
    import json

    parsed = parse_rule((FIXTURES / "artifact_sysnative_filters.yml").read_text())
    encoded = json.dumps(parsed.ir.to_dict())
    assert '"kind": "boolean"' in encoded and '"tier_name": "Host/network artifacts"' in encoded
