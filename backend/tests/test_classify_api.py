"""The /api/classify route: auth gate, result shape, structured parse errors, size cap."""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SYSNATIVE = (FIXTURES / "artifact_sysnative_filters.yml").read_text(encoding="utf-8")


def test_classify_requires_session(client) -> None:
    assert client.post("/api/classify", json={"rule": SYSNATIVE}).status_code == 401


def test_classify_returns_every_card_slot(authed_client) -> None:
    r = authed_client.post("/api/classify", json={"rule": SYSNATIVE})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["error"] is None
    assert set(body) == {"ok", "error", "ast", "scope", "pyramid", "lint", "attack"}
    ast = body["ast"]
    assert ast["provenance"] == "deterministic:ast"
    assert ast["root"]["kind"] == "boolean" and ast["root"]["op"] == "and"
    assert ast["selections"] == ["selection", "filter_main_ngen", "filter_optional_xampp"]
    assert ast["metadata"]["title"] == "Process Creation Using Sysnative Folder"
    assert body["scope"]["filter_count"] == 2
    assert body["pyramid"]["tier"] == 4 and body["pyramid"]["provenance"] == "deterministic:ast"
    assert body["lint"]["provenance"] == "deterministic:metadata" and body["lint"]["counts"]["error"] == 0
    assert body["attack"]["techniques"][0]["id"] == "T1055" and body["attack"]["provenance"] == "deterministic:metadata"


def test_parse_failure_is_a_result_not_an_http_error(authed_client) -> None:
    r = authed_client.post("/api/classify", json={"rule": "title: x\n  bad: [unclosed"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "invalid_yaml"
    assert body["error"]["detail"].startswith("line 2")
    assert body["ast"] is None and body["scope"] is None


def test_multi_document_paste_rejected_structurally(authed_client) -> None:
    body = authed_client.post("/api/classify", json={"rule": SYSNATIVE + "\n---\n" + SYSNATIVE}).json()
    assert body["ok"] is False and body["error"]["code"] == "multiple_rules"


def test_oversize_body_is_413_before_parsing(authed_client) -> None:
    huge = "# " + "x" * (70 * 1024)
    assert authed_client.post("/api/classify", json={"rule": huge}).status_code == 413


def test_empty_rule_is_422(authed_client) -> None:
    assert authed_client.post("/api/classify", json={"rule": ""}).status_code == 422


def test_metadata_errors_do_not_block_classification(authed_client) -> None:
    text = "title: bad\nid: nope\nstatus: bogus\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\nlevel: bogus\n"
    body = authed_client.post("/api/classify", json={"rule": text}).json()
    assert body["ok"] is True
    assert {e["type"] for e in body["ast"]["metadata_errors"]} >= {"SigmaIdentifierError", "SigmaLevelError", "SigmaStatusError"}
