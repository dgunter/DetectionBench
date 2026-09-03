from app.examples import load_examples


def test_examples_load_with_titles_and_yaml():
    examples = load_examples()
    ids = [e.id for e in examples]
    assert ids == [
        "hash_imphash_sharpevtmute",
        "ip_bare_not_zeek_rdp",
        "domain_dns_xmr_mining",
        "artifact_sysnative_filters",
        "relational_fieldref_delete_own_image",
    ]
    by_id = {e.id: e for e in examples}
    assert by_id["hash_imphash_sharpevtmute"].title == "HackTool - SharpEvtMute DLL Load"
    assert "condition:" in by_id["ip_bare_not_zeek_rdp"].yaml
    assert all(e.label and e.blurb for e in examples)


def test_examples_endpoint_requires_session(client):
    assert client.get("/api/examples").status_code == 401


def test_examples_endpoint_returns_rules(authed_client):
    r = authed_client.get("/api/examples")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 5
    assert set(body[0]) == {"id", "label", "blurb", "title", "yaml"}
