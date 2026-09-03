from app.pipeline.attack import load_attack_dataset
from app.pipeline.attack_map import map_attack_tags

DS = load_attack_dataset()


def _by_check(mapping):
    return {f.check: f for f in mapping.findings}


def test_valid_technique_and_tactic_resolve_cleanly():
    m = map_attack_tags(["attack.impact", "attack.t1496"], DS)
    assert m.findings == ()
    (t,) = m.techniques
    assert (t.id, t.status, t.name) == ("T1496", "valid", "Resource Hijacking")
    assert "impact" in t.tactics
    assert t.url == "https://attack.mitre.org/techniques/T1496"
    (tac,) = m.tactics
    assert (tac.name, tac.status) == ("impact", "valid")
    assert m.provenance == "deterministic:metadata"
    assert m.dataset_version == "19.2"


def test_subtechnique_resolves():
    m = map_attack_tags(["attack.t1685.001"], DS)
    (t,) = m.techniques
    assert t.status == "valid" and t.is_subtechnique and t.id == "T1685.001"


def test_retired_technique_reports_replacement():
    # T1562.002 (Disable Windows Event Logging) was revoked in v19 in favour of T1685.001.
    m = map_attack_tags(["attack.t1562.002"], DS)
    (t,) = m.techniques
    assert t.status == "retired"
    assert t.replaced_by == "T1685.001"
    assert t.replaced_by_name
    f = _by_check(m)["attack_technique_retired"]
    assert f.severity == "warning"
    assert "replaced by T1685.001" in f.message


def test_unknown_technique_is_an_error():
    m = map_attack_tags(["attack.t9999"], DS)
    (t,) = m.techniques
    assert t.status == "unknown" and t.name is None
    f = _by_check(m)["attack_technique_unknown"]
    assert f.severity == "error"


def test_software_and_group_tags_are_info_not_errors():
    m = map_attack_tags(["attack.s0002", "attack.g0016"], DS)
    assert m.unvalidated == ("attack.s0002", "attack.g0016")
    assert [f.severity for f in m.findings] == ["info", "info"]
    assert "not validated in v1" in m.findings[0].message


def test_tactic_underscore_form_accepted_and_v19_rename_flagged():
    m = map_attack_tags(["attack.privilege_escalation", "attack.defense-evasion", "attack.not-a-tactic"], DS)
    by_name = {t.name: t for t in m.tactics}
    assert by_name["privilege-escalation"].status == "valid"
    assert by_name["defense-evasion"].status == "renamed"
    assert by_name["defense-evasion"].renamed_to == "stealth"
    assert by_name["not-a-tactic"].status == "unknown"
    checks = _by_check(m)
    assert checks["attack_tactic_renamed"].severity == "warning"
    assert checks["attack_tactic_unknown"].severity == "error"


def test_non_attack_namespaces_pass_through_and_malformed_attack_tags_error():
    m = map_attack_tags(["cve.2021-44228", "detection.threat-hunting", "tlp.white", "attack.t12"], DS)
    assert m.other_tags == ("cve.2021-44228", "detection.threat-hunting", "tlp.white")
    assert _by_check(m)["attack_tag_malformed"].severity == "error"


def test_duplicate_tags_reported_once():
    m = map_attack_tags(["attack.t1055", "attack.T1055"], DS)
    assert len(m.techniques) == 1
    assert _by_check(m)["attack_tag_duplicate"].severity == "info"


def test_to_dict_is_json_shaped():
    d = map_attack_tags(["attack.stealth", "attack.t1055"], DS).to_dict()
    assert d["declared_count"] == 2
    assert d["techniques"][0]["name"] == "Process Injection"
    assert d["tactics"][0] == {"tag": "attack.stealth", "name": "stealth", "status": "valid", "renamed_to": None}
