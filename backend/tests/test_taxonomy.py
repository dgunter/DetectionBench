"""Field -> tier taxonomy, table-driven."""

from __future__ import annotations

import pytest

from app.pipeline.ir import LogSource
from app.pipeline.taxonomy import classify_leaf, load_tool_list

WIN_PROC = LogSource(category="process_creation", product="windows")
DNS = LogSource(category="dns")
AWS = LogSource(product="aws", service="cloudtrail")


@pytest.mark.parametrize(
    ("field", "value_type", "values", "modifiers", "logsource", "tier", "category"),
    [
        ("Hashes", "string", ("IMPHASH=330768A4",), ("contains",), WIN_PROC, 1, "hash"),
        ("md5", "string", ("abc",), (), WIN_PROC, 1, "hash"),
        ("sha256", "string", ("abc",), (), WIN_PROC, 1, "hash"),
        ("Imphash", "string", ("abc",), (), WIN_PROC, 1, "hash"),
        ("file_hash", "string", ("abc",), (), WIN_PROC, 1, "hash"),
        ("SomeField", "string", ("SHA256=abc",), ("contains",), WIN_PROC, 1, "hash"),
        ("SourceIp", "string", ("1.2.3.4",), (), WIN_PROC, 2, "ip"),
        ("DestinationIp", "string", ("1.2.3.4",), (), WIN_PROC, 2, "ip"),
        ("IpAddress", "string", ("1.2.3.4",), (), WIN_PROC, 2, "ip"),
        ("id.orig_h", "cidr", ("10.0.0.0/8",), ("cidr",), LogSource(product="zeek"), 2, "ip"),
        ("id.resp_h", "string", ("1.2.3.4",), (), LogSource(product="zeek"), 2, "ip"),
        ("src_ip", "string", ("1.2.3.4",), (), LogSource(), 2, "ip"),
        ("c-ip", "string", ("1.2.3.4",), (), LogSource(), 2, "ip"),
        ("anything", "cidr", ("10.0.0.0/8",), ("cidr",), LogSource(), 2, "ip"),
        ("DestinationHostname", "string", ("evil.com",), (), WIN_PROC, 3, "domain"),
        ("QueryName", "string", ("evil.com",), (), WIN_PROC, 3, "domain"),
        ("query", "string", ("pool.minexmr.com",), ("contains",), DNS, 3, "domain"),
        ("answer", "string", ("x",), (), DNS, 3, "domain"),  # any field under logsource.category == dns
        ("dns_query", "string", ("x",), (), LogSource(), 3, "domain"),
        ("fqdn", "string", ("x",), (), LogSource(), 3, "domain"),
        ("SubjectDomainName", "string", ("CORP",), (), LogSource(product="windows", service="security"), 4, "host_artifact"),
        ("TargetDomainName", "string", ("CORP",), (), LogSource(product="windows", service="security"), 4, "host_artifact"),
        ("CommandLine", "string", ("-enc",), ("contains",), WIN_PROC, 4, "host_artifact"),
        ("Image", "string", ("\\mimikatz.exe",), ("endswith",), WIN_PROC, 4, "host_artifact"),
        ("OriginalFileName", "string", ("mimikatz.exe",), (), WIN_PROC, 5, "tool"),
        ("Product", "string", ("Cobalt Strike",), ("contains",), WIN_PROC, 5, "tool"),
        ("Description", "string", ("Rubeus",), (), WIN_PROC, 5, "tool"),
        ("Company", "string", ("Nothing offensive",), (), WIN_PROC, 4, "host_artifact"),
        ("TargetFilename", "fieldref", ("Image",), ("fieldref",), LogSource(product="windows", category="file_delete"), 4, "relational"),
        ("eventName", "string", ("DeleteTrail",), (), AWS, 4, "behavioral"),
        ("operationName", "string", ("x",), (), LogSource(product="azure"), 4, "behavioral"),
        ("protoPayload.methodName", "string", ("x",), (), LogSource(product="gcp"), 4, "behavioral"),
        ("eventType", "string", ("user.mfa.factor.deactivate",), (), LogSource(product="okta"), 4, "behavioral"),
        ("eventName", "string", ("x",), (), WIN_PROC, 4, "host_artifact"),  # only behavioral for cloud products
        ("Channel", "string", ("Security",), (), LogSource(product="windows"), 4, "host_artifact"),
        (None, "string", ("evil",), (), WIN_PROC, 4, "keyword"),
    ],
)
def test_classify_leaf(field, value_type, values, modifiers, logsource, tier, category) -> None:
    cls = classify_leaf(field, value_type, values, modifiers, logsource)
    assert (cls.tier, cls.category) == (tier, category)


def test_tool_hit_on_process_field_stays_tier_4_with_annotation() -> None:
    cls = classify_leaf("Image", "string", ("\\mimikatz.exe",), ("endswith",), WIN_PROC)
    assert cls.tier == 4 and cls.note and "recognized tool: mimikatz" in cls.note and cls.confidence == "high"


def test_tool_hit_on_pe_metadata_is_tier_5_medium() -> None:
    cls = classify_leaf("OriginalFileName", "string", ("SharpHound.exe",), (), WIN_PROC)
    assert cls.tier == 5 and cls.confidence == "medium" and "sharphound" in (cls.note or "")


def test_tool_names_match_on_token_boundaries() -> None:
    assert classify_leaf("OriginalFileName", "string", ("myempirebuilder.exe",), (), WIN_PROC).tier == 4
    assert classify_leaf("OriginalFileName", "string", ("Empire.exe",), (), WIN_PROC).tier == 5


def test_imphash_note_and_routing_flag() -> None:
    cls = classify_leaf("Hashes", "string", ("IMPHASH=abc",), ("contains",), WIN_PROC)
    assert cls.note and "imphash" in cls.note.lower()
    assert classify_leaf("Provider_Name", "string", ("x",), (), WIN_PROC).routing is True
    assert classify_leaf("EventID", "string", ("4688",), (), WIN_PROC).routing is True
    assert classify_leaf("CommandLine", "string", ("x",), (), WIN_PROC).routing is False


def test_outcome_fields_are_flagged_not_retiered() -> None:
    cls = classify_leaf("errorCode", "string", ("Success",), (), AWS)
    assert (cls.tier, cls.category, cls.outcome) == (4, "host_artifact", True)
    assert classify_leaf("properties.result", "string", ("success",), (), LogSource(product="azure")).outcome is True
    assert classify_leaf("eventName", "string", ("DeleteBucket",), (), AWS).outcome is False
    assert classify_leaf("CommandLine", "string", ("x",), (), WIN_PROC).outcome is False


def test_keyword_search_is_low_confidence() -> None:
    assert classify_leaf(None, "string", ("evil",), (), WIN_PROC).confidence == "low"


def test_tool_list_loads_and_is_lowercase() -> None:
    names = load_tool_list()
    assert "mimikatz" in names and all(n == n.lower() for n in names) and len(names) > 30
