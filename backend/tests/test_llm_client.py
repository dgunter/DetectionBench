"""AnthropicLlmClient against a stubbed SDK: request shape, error mapping, streaming.

The panel's user-facing failure states (timeout, rate limit, overload,
refusal, bad JSON) are all produced here, so each one gets a test that the
SDK exception or response shape maps to the right LlmError code and status.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx
import pytest

from app.llm.client import AnthropicLlmClient, LlmError, LlmReply

REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def message(text: str = "hello", stop_reason: str = "end_turn", **usage: int) -> Any:
    """A minimal stand-in for anthropic.types.Message."""
    content = [
        SimpleNamespace(type="text", text=text),
        SimpleNamespace(type="tool_use", text="ignored: not a text block"),
    ]
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=content,
        usage=SimpleNamespace(input_tokens=usage.get("input_tokens", 11), output_tokens=usage.get("output_tokens", 7)),
    )


def status_error(cls: type, status: int, body: dict[str, Any] | None = None) -> Exception:
    return cls("upstream said no", response=httpx.Response(status, request=REQUEST), body=body)


class FakeStream:
    def __init__(self, chunks: list[str], final: Any, fail_after: Exception | None = None) -> None:
        self._chunks = chunks
        self._final = final
        self._fail_after = fail_after

    @property
    def text_stream(self):
        yield from self._chunks
        if self._fail_after is not None:
            raise self._fail_after

    def get_final_message(self) -> Any:
        return self._final


class FakeMessages:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response: Any = message()
        self.error: Exception | None = None
        self.stream_chunks: list[str] = ["a", "b"]
        self.stream_error: Exception | None = None

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response

    @contextmanager
    def stream(self, **kwargs: Any):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        yield FakeStream(self.stream_chunks, self.response, self.stream_error)


class FakeAnthropic:
    """Replaces anthropic.Anthropic; records constructor args and with_options timeouts."""

    instances: list[FakeAnthropic] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.messages = FakeMessages()
        self.option_timeouts: list[float] = []
        FakeAnthropic.instances.append(self)

    def with_options(self, *, timeout: float) -> FakeAnthropic:
        self.option_timeouts.append(timeout)
        return self


@pytest.fixture
def sdk(monkeypatch) -> FakeAnthropic:
    FakeAnthropic.instances.clear()
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    AnthropicLlmClient(api_key="k", model="default-model", timeout_seconds=42.0)
    return FakeAnthropic.instances[-1]


@pytest.fixture
def llm(sdk) -> AnthropicLlmClient:
    client = AnthropicLlmClient.__new__(AnthropicLlmClient)
    client._client = sdk  # noqa: SLF001 (bind the recorded fake)
    client._model = "default-model"  # noqa: SLF001
    return client


def test_constructor_disables_sdk_retries_and_passes_timeout(sdk):
    assert sdk.kwargs == {"api_key": "k", "timeout": 42.0, "max_retries": 0}


def test_llm_error_carries_code_message_and_status():
    err = LlmError("rate_limited", "slow down", 429)
    assert (err.code, err.message, err.http_status, str(err)) == ("rate_limited", "slow down", 429, "slow down")
    assert err.to_dict() == {"code": "rate_limited", "message": "slow down"}
    assert LlmError("x", "y").http_status == 502


def test_complete_joins_text_blocks_and_reports_usage(llm, sdk):
    sdk.messages.response = message("  two words  ", input_tokens=3, output_tokens=5)
    reply = llm.complete(system="sys", user="usr", max_tokens=99)
    assert reply == LlmReply("two words", 3, 5)
    call = sdk.messages.calls[-1]
    assert call["model"] == "default-model"
    assert call["max_tokens"] == 99
    assert call["messages"] == [{"role": "user", "content": "usr"}]
    assert call["system"][0]["text"] == "sys"
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_complete_honours_model_override(llm, sdk):
    llm.complete(system="s", user="u", model="other-model")
    assert sdk.messages.calls[-1]["model"] == "other-model"


def test_refusal_becomes_a_422(llm, sdk):
    sdk.messages.response = message(stop_reason="refusal")
    with pytest.raises(LlmError) as info:
        llm.complete(system="s", user="u")
    assert (info.value.code, info.value.http_status) == ("refused", 422)


def test_complete_json_parses_output_and_sets_schema(llm, sdk):
    sdk.messages.response = message(json.dumps({"ok": True}))
    schema = {"type": "object"}
    assert llm.complete_json(system="s", user="u", schema=schema) == {"ok": True}
    call = sdk.messages.calls[-1]
    assert call["output_config"] == {"format": {"type": "json_schema", "schema": schema}}
    assert call["max_tokens"] == 8192
    assert sdk.option_timeouts == []  # no per-call timeout: the client default applies


def test_complete_json_effort_and_timeout_are_forwarded(llm, sdk):
    sdk.messages.response = message("{}")
    llm.complete_json(system="s", user="u", schema={}, effort="medium", timeout=120.0)
    assert sdk.messages.calls[-1]["output_config"]["effort"] == "medium"
    assert sdk.option_timeouts == [120.0]


def test_complete_json_rejects_non_json(llm, sdk):
    sdk.messages.response = message("not json {")
    with pytest.raises(LlmError) as info:
        llm.complete_json(system="s", user="u", schema={})
    assert (info.value.code, info.value.http_status) == ("bad_output", 502)


@pytest.mark.parametrize(
    "exc,code,status",
    [
        (anthropic.APITimeoutError(request=REQUEST), "timeout", 504),
        (status_error(anthropic.RateLimitError, 429), "rate_limited", 429),
        (status_error(anthropic.AuthenticationError, 401), "not_configured", 503),
        (status_error(anthropic.APIStatusError, 529, {"type": "overloaded_error"}), "overloaded", 503),
        (status_error(anthropic.InternalServerError, 500), "overloaded", 503),
        (status_error(anthropic.BadRequestError, 400), "api_error", 502),
        (anthropic.APIConnectionError(request=REQUEST), "unreachable", 502),
    ],
    ids=["timeout", "rate-limit", "auth", "overloaded", "5xx", "4xx", "connection"],
)
def test_sdk_errors_map_to_friendly_codes(llm, sdk, exc, code, status):
    sdk.messages.error = exc
    with pytest.raises(LlmError) as info:
        llm.complete(system="s", user="u")
    assert (info.value.code, info.value.http_status) == (code, status)
    assert info.value.__cause__ is exc


def test_stream_yields_deltas_and_checks_the_final_message(llm, sdk):
    sdk.messages.stream_chunks = ["Hel", "lo"]
    assert list(llm.stream(system="s", user="u", model="m")) == ["Hel", "lo"]
    call = sdk.messages.calls[-1]
    assert call["model"] == "m"
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_stream_refusal_surfaces_after_the_deltas(llm, sdk):
    sdk.messages.stream_chunks = ["partial"]
    sdk.messages.response = message(stop_reason="refusal")
    it = llm.stream(system="s", user="u")
    assert next(it) == "partial"
    with pytest.raises(LlmError) as info:
        next(it)
    assert info.value.code == "refused"


def test_stream_maps_midstream_sdk_errors(llm, sdk):
    sdk.messages.stream_chunks = ["x"]
    sdk.messages.stream_error = status_error(anthropic.RateLimitError, 429)
    it = llm.stream(system="s", user="u")
    assert next(it) == "x"
    with pytest.raises(LlmError) as info:
        next(it)
    assert info.value.code == "rate_limited"
