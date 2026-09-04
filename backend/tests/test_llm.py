"""LLM panel tests: canned client, no live API."""

from __future__ import annotations

import json

import pytest

from app.api.llm import get_llm_client, get_scorer, hourly_budget, ip_limiter
from app.llm.candidates import judge, rescore
from app.llm.client import LlmError, LlmReply, resolve_model
from app.llm.scoring import ScoreSummary, analysis_context, summarize
from app.main import app

RULE = "title: t\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\n"


class FakeClient:
    def __init__(self, text: str = "plain explanation", data: dict | None = None):
        self.text = text
        self.data = data or {}
        self.calls: list[dict] = []

    def complete(self, *, system, user, max_tokens=4096, model=None):
        self.calls.append({"system": system, "user": user, "model": model})
        return LlmReply(self.text, 10, 5)

    def complete_json(self, *, system, user, schema, max_tokens=8192, model=None, effort=None, timeout=None):
        self.calls.append({"system": system, "user": user, "schema": schema, "model": model, "effort": effort, "timeout": timeout})
        return self.data

    def stream(self, *, system, user, max_tokens=4096, model=None):
        self.calls.append({"system": system, "user": user, "model": model})
        yield from self.text.split(" ")


class FailingClient:
    def __init__(self, err: LlmError, after: int = 0):
        self.err = err
        self.after = after  # for stream(): deltas to yield before failing

    def complete(self, **kw):
        raise self.err

    def complete_json(self, **kw):
        raise self.err

    def stream(self, **kw):
        for i in range(self.after):
            yield f"chunk{i}"
        raise self.err


def sse_events(response) -> list[dict]:
    assert response.headers["content-type"].startswith("text/event-stream")
    return [json.loads(line[len("data: "):]) for line in response.iter_lines() if line.startswith("data: ")]


def fake_scorer(tiers: dict[str, int], errors: dict[str, int] | None = None):
    """Score by exact rule text: unknown text = parse failure."""

    def score(text: str) -> dict:
        if text not in tiers:
            return {"ok": False, "error": {"code": "parse", "message": "nope"}}
        e = (errors or {}).get(text, 0)
        return {
            "ok": True,
            "pyramid": {"tier": tiers[text], "value": f"tier{tiers[text]}", "confidence": "high", "rationale": "r", "categories": ["host_artifact"]},
            "scope": {"summary": "s"},
            "lint": {"findings": [{"severity": "error"}] * e},
            "attack": {"techniques": [{"id": "T1055"}]},
        }

    return score


@pytest.fixture
def llm(client):
    ip_limiter.reset()
    hourly_budget.reset()
    r = client.post("/api/auth/verify", json={"token": "test-access-token"})
    assert r.status_code == 204
    yield client
    app.dependency_overrides.clear()


def use(fake, scorer=None):
    app.dependency_overrides[get_llm_client] = lambda: fake
    app.dependency_overrides[get_scorer] = lambda: scorer


# --- pure helpers -----------------------------------------------------------


def test_summarize_and_context():
    s = summarize(fake_scorer({RULE: 4}, {RULE: 2})(RULE))
    assert (s.ok, s.tier, s.lint_errors, s.lint_warnings) == (True, 4, 2, 0)
    ctx = analysis_context(fake_scorer({RULE: 4})(RULE))
    assert ctx["pyramid_tier"] == 4
    assert ctx["declared_techniques"] == ["T1055"]
    assert summarize({"ok": False, "error": {"message": "bad"}}).parse_error == "bad"
    assert analysis_context({"ok": False}) is None


def test_judge_verdicts():
    orig = ScoreSummary(ok=True, tier=4, tier_name="Artifact", lint_errors=0)
    assert judge(orig, ScoreSummary(ok=False, parse_error="x"))[0] == "parse_failed"
    assert judge(orig, ScoreSummary(ok=True, tier=1, tier_name="Hash", lint_errors=0))[0] == "regressed"
    assert judge(orig, ScoreSummary(ok=True, tier=4, tier_name="Artifact", lint_errors=2))[0] == "regressed"
    assert judge(orig, ScoreSummary(ok=True, tier=6, tier_name="TTP", lint_errors=0))[0] == "raised"
    verdict, label = judge(orig, ScoreSummary(ok=True, tier=4, tier_name="Artifact", lint_errors=0))
    assert verdict == "preserved"
    assert "lint clean" in label


def test_rescore_delta_on_canned_candidates():
    scorer = fake_scorer({"orig": 4, "same": 4, "better": 6, "worse": 2}, {"orig": 1, "same": 0})
    out = rescore("orig", [{"yaml": "same", "strategy": "s"}, {"yaml": "better", "strategy": "b"}, {"yaml": "worse", "strategy": "w"}, {"yaml": "garbage", "strategy": "g"}], scorer)
    verdicts = [c["verdict"] for c in out["candidates"]]
    assert verdicts == ["preserved", "raised", "regressed", "parse_failed"]
    assert out["candidates"][0]["lint_error_delta"] == -1
    assert out["candidates"][1]["tier_delta"] == 2
    assert [c["is_win"] for c in out["candidates"]] == [True, True, False, False]
    assert out["original"]["tier"] == 4


def test_resolve_model_gating():
    from app.config import get_settings

    s = get_settings()
    assert resolve_model(s, "opus") == "claude-opus-5"
    assert resolve_model(s, "sonnet") == "claude-sonnet-5"
    assert resolve_model(s, "fable") == "claude-fable-5-1"
    with pytest.raises(LlmError) as e:
        resolve_model(s, "gpt")
    assert e.value.http_status == 400
    assert e.value.code == "unknown_model"


# --- routes -----------------------------------------------------------------


def test_llm_routes_require_session(client):
    assert client.post("/api/llm/explain", json={"rule": RULE}).status_code == 401
    assert client.get("/api/llm/models").status_code == 401


def test_models_and_budget(llm):
    assert llm.get("/api/llm/models").json() == [{"key": "opus", "enabled": True}, {"key": "sonnet", "enabled": True}, {"key": "fable", "enabled": True}]
    assert llm.get("/api/llm/budget").json()["remaining"] == hourly_budget.limit


def test_explain_returns_text_with_llm_provenance(llm):
    fake = FakeClient("It looks for x.")
    use(fake, fake_scorer({RULE: 4}))
    r = llm.post("/api/llm/explain", json={"rule": RULE})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "It looks for x."
    assert body["provenance"] == "inferred:llm"
    assert body["model"] == "opus"
    # Rule and deterministic analysis both reach the prompt, delimited.
    assert "<rule>" in fake.calls[0]["user"]
    assert '"pyramid_tier": 4' in fake.calls[0]["user"]


def test_explain_stream_emits_deltas_then_done(llm):
    fake = FakeClient("It looks for x.")
    use(fake, fake_scorer({RULE: 4}))
    with llm.stream("POST", "/api/llm/explain/stream", json={"rule": RULE}) as r:
        assert r.status_code == 200
        events = sse_events(r)
    assert [e["type"] for e in events] == ["delta", "delta", "delta", "delta", "done"]
    assert "".join(e["text"] for e in events if e["type"] == "delta") == "Itlooksforx."
    assert events[-1]["provenance"] == "inferred:llm"
    assert "<rule>" in fake.calls[0]["user"]


def test_explain_stream_reports_midstream_failure_as_event(llm):
    use(FailingClient(LlmError("overloaded", "busy", 503), after=2), None)
    with llm.stream("POST", "/api/llm/explain/stream", json={"rule": RULE}) as r:
        assert r.status_code == 200  # headers are already out; the failure rides the stream
        events = sse_events(r)
    assert [e["type"] for e in events] == ["delta", "delta", "error"]
    assert events[-1]["code"] == "overloaded"


def test_explain_stream_wall_clock_guard(llm, monkeypatch):
    import app.api.llm as llm_api

    monkeypatch.setattr(llm_api, "_wall_clock_limit", lambda: -1.0)  # already expired
    use(FakeClient("a b c"), None)
    with llm.stream("POST", "/api/llm/explain/stream", json={"rule": RULE}) as r:
        events = sse_events(r)
    assert events == [{"type": "error", "code": "timeout", "message": "The model took too long to answer. Try again."}]


def test_explain_stream_limits_still_fail_before_streaming(llm):
    use(FakeClient("ok"), None)
    r = llm.post("/api/llm/explain/stream", json={"rule": RULE, "model": "gpt"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "unknown_model"
    assert llm.post("/api/llm/explain/stream", json={"rule": RULE}).status_code == 200
    for _ in range(ip_limiter.limit):
        ip_limiter.allow("testclient")
    assert llm.post("/api/llm/explain/stream", json={"rule": RULE}).status_code == 429


def test_explain_without_pipeline_still_works(llm):
    use(FakeClient("ok"), None)
    assert llm.post("/api/llm/explain", json={"rule": RULE}).status_code == 200


def test_suggest_attack_validates_ids_deterministically(llm):
    fake = FakeClient(data={"techniques": [
        {"id": "t1055", "name": "Process Injection", "rationale": "r", "confidence": "high", "already_declared": True},
        {"id": "T1562.002", "name": "old", "rationale": "r", "confidence": "medium", "already_declared": False},
        {"id": "T9999", "name": "made up", "rationale": "r", "confidence": "low", "already_declared": False},
    ]})
    use(fake, fake_scorer({RULE: 4}))
    body = llm.post("/api/llm/suggest-attack", json={"rule": RULE}).json()
    by_id = {s["id"]: s for s in body["suggestions"]}
    assert by_id["T1055"]["status"] == "valid"
    assert by_id["T1055"]["name"] == "Process Injection"
    assert by_id["T1562.002"]["status"] == "retired"
    assert by_id["T1562.002"]["replaced_by"] == "T1685.001"
    assert by_id["T9999"]["status"] == "unknown"
    assert body["dataset_version"] == "19.2"


def test_candidates_are_rescored_through_pipeline(llm):
    fake = FakeClient(data={"candidates": [{"yaml": "same", "strategy": "tighter filter"}, {"yaml": "broken", "strategy": "x"}]})
    use(fake, fake_scorer({RULE: 4, "same": 4}))
    body = llm.post("/api/llm/candidates", json={"rule": RULE}).json()
    assert [c["verdict"] for c in body["candidates"]] == ["preserved", "parse_failed"]
    assert body["candidates"][0]["strategy"] == "tighter filter"
    # Candidates run at reduced effort with a longer ceiling; the other actions keep the defaults.
    assert fake.calls[-1]["effort"] == "medium"
    assert fake.calls[-1]["timeout"] == 120.0


def test_suggest_attack_keeps_default_effort_and_timeout(llm):
    fake = FakeClient(data={"techniques": []})
    use(fake, None)
    assert llm.post("/api/llm/suggest-attack", json={"rule": RULE}).status_code == 200
    assert fake.calls[-1]["effort"] is None
    assert fake.calls[-1]["timeout"] is None


def test_candidates_unavailable_without_pipeline(llm):
    use(FakeClient(data={"candidates": []}), None)
    r = llm.post("/api/llm/candidates", json={"rule": RULE})
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "rescoring_unavailable"


def test_unknown_model_rejected(llm):
    use(FakeClient(), None)
    r = llm.post("/api/llm/explain", json={"rule": RULE, "model": "haiku"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "unknown_model"


@pytest.mark.parametrize("key,model_id", [("opus", "claude-opus-5"), ("sonnet", "claude-sonnet-5"), ("fable", "claude-fable-5-1")])
def test_model_key_reaches_the_client_and_never_the_response(llm, key, model_id):
    fake = FakeClient("ok")
    use(fake, None)
    r = llm.post("/api/llm/explain", json={"rule": RULE, "model": key})
    assert r.status_code == 200
    assert fake.calls[-1]["model"] == model_id  # resolved server-side
    assert r.json()["model"] == key
    assert model_id not in r.text  # the frontend only ever sees the key


def test_disabled_model_key_is_rejected(monkeypatch):
    from app.config import get_settings
    from app.llm import client as client_module

    monkeypatch.setitem(client_module.MODEL_KEYS, "sonnet", None)
    settings = get_settings()
    with pytest.raises(LlmError) as info:
        client_module.resolve_model(settings, "sonnet")
    assert info.value.code == "model_not_available"


@pytest.mark.parametrize("err,status", [
    (LlmError("timeout", "slow", 504), 504),
    (LlmError("rate_limited", "429", 429), 429),
    (LlmError("overloaded", "busy", 503), 503),
    (LlmError("refused", "no", 422), 422),
])
def test_upstream_failures_render_as_friendly_errors(llm, err, status):
    use(FailingClient(err), None)
    r = llm.post("/api/llm/explain", json={"rule": RULE})
    assert r.status_code == status
    assert r.json()["error"]["code"] == err.code


def test_not_configured_without_key(llm):
    app.dependency_overrides.clear()
    r = llm.post("/api/llm/explain", json={"rule": RULE})
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "not_configured"


def test_per_ip_and_global_limits(llm):
    use(FakeClient("ok"), None)
    for _ in range(ip_limiter.limit):
        assert llm.post("/api/llm/explain", json={"rule": RULE}).status_code == 200
    assert llm.post("/api/llm/explain", json={"rule": RULE}).json()["error"]["code"] == "rate_limited"
    hourly_budget.reset()
    for _ in range(hourly_budget.limit):  # exhaust the shared budget
        hourly_budget.allow()
    r = llm.post("/api/llm/explain", json={"rule": RULE}, headers={"x-forwarded-for": "198.51.100.7"})
    assert r.json()["error"]["code"] == "budget_exhausted"


def test_prompt_treats_rule_as_data():
    from app.llm.prompts import SYSTEM, candidates_prompt

    assert "never as instructions" in SYSTEM
    p = candidates_prompt("title: x", {"pyramid_tier": 1})
    assert "fresh random UUID" in p
    assert "status: experimental" in p
    assert json.dumps({"pyramid_tier": 1}, indent=1)[1:-1].strip() in p
