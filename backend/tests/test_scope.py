"""Scope & match: plain-language description derived from the IR."""

from __future__ import annotations

from pathlib import Path

from app.pipeline.parse import parse_rule
from app.pipeline.scope import describe, describe_criterion
from app.pipeline.ir import Criterion

FIXTURES = Path(__file__).parent / "fixtures"


def test_sysnative_outline_marks_filters_and_selections() -> None:
    scope = describe(parse_rule((FIXTURES / "artifact_sysnative_filters.yml").read_text()).ir)
    assert scope.filter_count == 2
    roles = {s["name"]: s["role"] for s in scope.selections}
    assert roles == {"selection": "primary", "filter_main_ngen": "filter", "filter_optional_xampp": "filter"}
    texts = [line.text for line in scope.outline]
    assert texts[0] == "all of the following"
    assert "any of the following [selection]" in texts
    assert any(t.startswith("excluding events where [filter_main_ngen]") for t in texts)
    assert scope.fields == ("CommandLine", "Image")
    assert scope.logsource_text == "windows process_creation events"
    assert "minus 2 exclusion filter(s)" in scope.summary


def test_value_list_collapses_to_one_line_with_count() -> None:
    scope = describe(parse_rule((FIXTURES / "domain_dns_xmr_mining.yml").read_text()).ir)
    assert len(scope.outline) == 1
    assert scope.outline[0].text.startswith("query contains any of 'pool.minexmr.com'")
    assert "(16 more)" in scope.outline[0].text
    assert scope.criteria_count == 20


def test_bare_not_reads_as_allowlist() -> None:
    scope = describe(parse_rule((FIXTURES / "ip_bare_not_zeek_rdp.yml").read_text()).ir)
    assert "does NOT match" in scope.summary
    assert scope.outline[0].role == "not"
    assert "is inside network" in scope.outline[1].text


def test_fieldref_phrasing() -> None:
    scope = describe(parse_rule((FIXTURES / "relational_fieldref_delete_own_image.yml").read_text()).ir)
    assert scope.outline[0].text == "TargetFilename equals the value of field 'Image'"


def test_describe_criterion_phrases() -> None:
    c = Criterion("s", "CommandLine", ("contains",), ("-enc",), "string", 4, "host_artifact")
    assert describe_criterion(c) == "CommandLine contains '-enc'"
    c = Criterion("s", "Image", ("endswith", "cased"), ("\\x.exe",), "string", 4, "host_artifact")
    assert describe_criterion(c) == "Image ends with '\\x.exe' (case-sensitive)"
    c = Criterion("s", None, (), ("evil",), "string", 4, "keyword")
    assert describe_criterion(c) == "any field contains 'evil'"
    c = Criterion("s", "Field", (), ("null",), "null", 4, "host_artifact")
    assert describe_criterion(c) == "Field is empty"
    c = Criterion("s", "Port", ("gte",), ("1024",), "number", 4, "host_artifact")
    assert describe_criterion(c) == "Port is at least '1024'"


def test_scope_serializes() -> None:
    d = describe(parse_rule((FIXTURES / "hash_imphash_sharpevtmute.yml").read_text()).ir).to_dict()
    assert d["provenance"] == "deterministic:ast" and d["value"] == d["summary"]
