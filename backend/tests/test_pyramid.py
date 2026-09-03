"""Boolean resolution, table-driven over hand-built IR trees.

These are the strongest evidence that the classifier does what the
methodology page claims: AND-min, OR-max, filter exclusion, bare NOT, TTP
escalation allowed / blocked, fieldref, and the always-on advisories.
"""

from __future__ import annotations

import pytest

from app.pipeline.ir import Boolean, Criterion, LogSource, Metadata, RuleIR
from app.pipeline.pyramid import classify, resolve


def crit(field: str, tier: int, category: str, *, selection: str = "selection", confidence: str = "high", routing: bool = False) -> Criterion:
    return Criterion(selection, field, ("contains",), ("v",), "string", tier, category, confidence, None, routing)


HASH = crit("Hashes", 1, "hash")
IP = crit("SourceIp", 2, "ip")
DOMAIN = crit("DestinationHostname", 3, "domain")
CMD = crit("CommandLine", 4, "host_artifact")
IMAGE = crit("Image", 4, "host_artifact")
PE_TOOL = crit("OriginalFileName", 5, "tool", confidence="medium")
FIELDREF = Criterion("selection", "TargetFilename", ("fieldref",), ("Image",), "fieldref", 4, "relational", "medium")
CLOUD = crit("eventName", 4, "behavioral")
CHANNEL = crit("Channel", 4, "host_artifact", selection="selection_channel", routing=True)
ERRORCODE = Criterion("selection_status", "errorCode", (), ("Success",), "string", 4, "host_artifact", "high", None, False, True)
KEYWORD = Criterion("keywords", None, (), ("touch",), "string", 4, "keyword", "low")
MFA_USED = crit("additionalEventData.MFAUsed", 4, "host_artifact")
EVENTID = crit("EventID", 4, "host_artifact", selection="selection_event", routing=True)


def AND(*children, selection=None):
    return Boolean("and", tuple(children), selection)


def OR(*children, selection=None):
    return Boolean("or", tuple(children), selection)


def NOT(child):
    return Boolean("not", (child,))


def ir(root, level: str | None = None) -> RuleIR:
    return RuleIR(Metadata(title="t", level=level, logsource=LogSource(product="windows", category="process_creation")), "selection", root, ("selection",))


@pytest.mark.parametrize(
    ("name", "root", "tier", "confidence"),
    [
        ("single hash", HASH, 1, "high"),
        ("AND -> min: hash AND command line", AND(HASH, CMD), 1, "high"),
        ("AND -> min: domain AND ip", AND(DOMAIN, IP), 2, "high"),
        ("OR -> max: hash OR command line", OR(HASH, CMD), 4, "high"),
        ("OR -> max: ip OR domain", OR(IP, DOMAIN), 3, "high"),
        ("nested: (hash OR cmd) AND image", AND(OR(HASH, CMD), IMAGE), 4, "high"),
        ("nested: (hash AND cmd) OR domain", OR(AND(HASH, CMD), DOMAIN), 3, "high"),
        ("filter excluded: cmd AND NOT hash", AND(CMD, NOT(HASH)), 4, "high"),
        ("filter excluded: cmd AND NOT ip AND NOT domain", AND(CMD, NOT(IP), NOT(DOMAIN)), 4, "high"),
        ("bare NOT over ip list -> ip tier, medium", NOT(OR(IP, IP)), 2, "medium"),
        ("bare NOT over cmd -> tier 4, medium", NOT(CMD), 4, "medium"),
        ("all-negated AND: NOT ip AND NOT cmd -> both primary, min", AND(NOT(IP), NOT(CMD)), 2, "medium"),
        ("TTP escalation: cmd AND cloud action (2 categories, all >= 4)", AND(CMD, CLOUD), 6, "medium"),
        ("TTP escalation: cmd AND fieldref", AND(CMD, FIELDREF), 6, "medium"),
        ("TTP escalation: cmd AND PE tool", AND(CMD, PE_TOOL), 6, "medium"),
        ("TTP escalation survives a filter", AND(CMD, CLOUD, NOT(HASH)), 6, "medium"),
        ("no escalation: same category (image AND cmd)", AND(IMAGE, CMD), 4, "high"),
        ("no escalation: single branch", AND(CMD), 4, "high"),
        ("escalation blocked by tier-1 branch", AND(HASH, CMD, CLOUD), 1, "high"),
        ("escalation blocked by tier-3 branch", AND(DOMAIN, CMD, CLOUD), 3, "high"),
        ("escalation is not applied to OR", OR(CMD, CLOUD), 4, "high"),
        ("escalated AND inside OR carries tier 6", OR(HASH, AND(CMD, CLOUD)), 6, "medium"),
        ("escalated AND inside AND is floored by sibling", AND(IP, AND(CMD, CLOUD)), 2, "high"),
        ("fieldref alone -> tier 4 medium", FIELDREF, 4, "medium"),
        ("PE tool alone -> tier 5 medium", PE_TOOL, 5, "medium"),
        ("routing field still floors (advisory only)", AND(CHANNEL, PE_TOOL), 4, "high"),
        ("D2: cloud action AND outcome field is not a chain", AND(CLOUD, ERRORCODE), 4, "high"),
        ("D2: cloud action AND OR of outcome fields is not a chain", AND(CLOUD, OR(ERRORCODE, ERRORCODE)), 4, "high"),
        ("D2: artifact AND keyword is not a chain (keyword bottleneck drags confidence to low)", AND(CMD, KEYWORD), 4, "low"),
        ("D2: cloud action AND attacker-controllable qualifier still escalates", AND(CLOUD, MFA_USED), 6, "medium"),
        ("D2: outcome branch never blocks escalation of two real branches", AND(CMD, CLOUD, ERRORCODE), 6, "medium"),
        ("allowlist in disguise: EventID AND NOT ip list -> the NOT is primary, ip tier, medium", AND(EVENTID, NOT(OR(IP, IP))), 2, "medium"),
        ("allowlist in disguise: outcome AND NOT cmd -> tier 4, medium", AND(ERRORCODE, NOT(CMD)), 4, "medium"),
        ("allowlist in disguise: two NOTs both primary, min", AND(EVENTID, NOT(CMD), NOT(DOMAIN)), 3, "medium"),
        ("a real positive branch keeps the NOT an excluded filter", AND(EVENTID, CMD, NOT(IP)), 4, "high"),
        ("nested allowlist AND inside OR carries its tier", OR(HASH, AND(EVENTID, NOT(DOMAIN))), 3, "medium"),
    ],
)
def test_resolution(name: str, root, tier: int, confidence: str) -> None:
    res = resolve(root)
    assert (res.tier, res.confidence) == (tier, confidence), f"{name}: {res.steps}"


def test_classify_result_shape_and_provenance() -> None:
    result = classify(ir(AND(CMD, NOT(HASH))))
    d = result.to_dict()
    assert d["provenance"] == "deterministic:ast"
    assert d["tier"] == 4 and d["value"] == "Host/network artifacts" and d["confidence"] == "high"
    assert d["rationale"] and d["steps"]


def test_filter_advisory_lists_filters_and_names_cheapest() -> None:
    result = classify(ir(AND(CMD, NOT(HASH), NOT(AND(IMAGE, CMD, selection="filter_x")))))
    adv = [a for a in result.advisories if a.kind == "filter"]
    assert len(adv) == 1
    assert adv[0].detail["cheapest"] == "`selection`"  # the NOT(HASH) filter, tier 1
    assert [f["tier"] for f in adv[0].detail["filters"]] == [1, 4]
    assert result.tier == 4  # filters never change the tier


def test_no_filter_advisory_without_filters() -> None:
    assert not [a for a in classify(ir(AND(CMD, IMAGE))).advisories if a.kind == "filter"]


def test_routing_advisory_does_not_change_score() -> None:
    result = classify(ir(AND(CHANNEL, PE_TOOL)))
    kinds = [a.kind for a in result.advisories]
    assert "routing" in kinds and result.tier == 4


def test_bare_not_advisory() -> None:
    result = classify(ir(NOT(OR(IP, IP))))
    assert [a.kind for a in result.advisories if a.kind == "bare_not"] == ["bare_not"]
    assert "allowlist" in result.steps[0]


def test_allowlist_in_disguise_is_scored_and_advised_not_filtered() -> None:
    result = classify(ir(AND(EVENTID, NOT(OR(IP, IP)), selection=None)))
    kinds = [a.kind for a in result.advisories]
    assert "bare_not" in kinds and "filter" not in kinds  # the NOT is scored, so it is not an excluded filter
    assert result.tier == 2 and result.confidence == "medium"
    assert "allowlist" in result.steps[0] and "primary logic" in result.steps[0]


def test_allowlist_in_disguise_does_not_trigger_for_real_positives() -> None:
    result = classify(ir(AND(EVENTID, CMD, NOT(IP))))
    kinds = [a.kind for a in result.advisories]
    assert "filter" in kinds and "bare_not" not in kinds


@pytest.mark.parametrize(
    ("level", "root", "expected"),
    [
        ("high", HASH, True),
        ("critical", IP, True),
        ("high", DOMAIN, True),
        ("high", CMD, False),
        ("medium", HASH, False),
        (None, HASH, False),
    ],
)
def test_level_vs_tier_advisory(level, root, expected) -> None:
    kinds = [a.kind for a in classify(ir(root, level)).advisories]
    assert ("level_vs_tier" in kinds) is expected


def test_ttp_escalation_rationale_says_medium_and_why() -> None:
    result = classify(ir(AND(CMD, CLOUD)))
    assert result.confidence == "medium"
    assert any("TTP escalation" in s and "medium" in s for s in result.steps)
    assert set(result.categories) == {"host_artifact", "behavioral"}


def test_min_rule_trace_names_the_bottleneck() -> None:
    result = classify(ir(AND(HASH, CMD, CLOUD)))
    assert result.tier == 1
    assert any("floored at tier 1" in s for s in result.steps)
