"""Server-side Claude client.

The frontend never sees the model ID or the API key; it sends a model *key*
("opus") and the backend resolves it here. Every failure mode that a user can
hit (rate limit, overload, timeout, refusal) becomes an ``LlmError`` with a
short code so the panel renders a friendly state instead of a blank card.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Protocol

import anthropic

from app.config import Settings

# Model keys the UI may send. Only Opus is wired for v1; the others are shown
# as "soon" in the UI and rejected here so the flag flip is a one-line change.
MODEL_KEYS: dict[str, str | None] = {"opus": "claude-opus-5", "sonnet": None, "fable": None}


class LlmError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class LlmReply:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class LlmClient(Protocol):
    def complete(self, *, system: str, user: str, max_tokens: int = 4096) -> LlmReply: ...

    def complete_json(self, *, system: str, user: str, schema: dict[str, Any], max_tokens: int = 8192) -> dict[str, Any]: ...

    def stream(self, *, system: str, user: str, max_tokens: int = 4096) -> Iterator[str]:
        """Yield text deltas as they arrive. Raises LlmError, possibly mid-stream."""
        ...


def resolve_model(settings: Settings, model_key: str) -> str:
    if model_key not in MODEL_KEYS:
        raise LlmError("unknown_model", f"unknown model '{model_key}'", 400)
    model_id = MODEL_KEYS[model_key]
    if model_id is None:
        raise LlmError("model_not_available", f"{model_key} isn't available yet; use opus", 400)
    return settings.llm_model if model_key == "opus" else model_id


class AnthropicLlmClient:
    def __init__(self, api_key: str, model: str, timeout_seconds: float = 60.0) -> None:
        # One retry only: the 60 s budget is the user-facing promise and retries stack on it.
        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout_seconds, max_retries=1)
        self._model = model

    @staticmethod
    @contextmanager
    def _mapped_errors() -> Iterator[None]:
        """Translate SDK exceptions into user-facing LlmErrors (most specific first)."""
        try:
            yield
        except anthropic.APITimeoutError as exc:
            raise LlmError("timeout", "The model took too long to answer. Try again.", 504) from exc
        except anthropic.RateLimitError as exc:
            raise LlmError("rate_limited", "The model is rate-limited right now. Try again in a minute.", 429) from exc
        except anthropic.AuthenticationError as exc:
            raise LlmError("not_configured", "The AI panel isn't configured on this server.", 503) from exc
        except anthropic.APIStatusError as exc:
            if exc.type == "overloaded_error" or exc.status_code >= 500:
                raise LlmError("overloaded", "The model is overloaded right now. Try again shortly.", 503) from exc
            raise LlmError("api_error", "The model request was rejected.", 502) from exc
        except anthropic.APIConnectionError as exc:
            raise LlmError("unreachable", "Couldn't reach the model service.", 502) from exc

    @staticmethod
    def _check_refusal(response: anthropic.types.Message) -> None:
        if response.stop_reason == "refusal":
            raise LlmError("refused", "The model declined to answer this request.", 422)

    def _create(self, **kwargs: Any) -> anthropic.types.Message:
        with self._mapped_errors():
            response = self._client.messages.create(model=self._model, **kwargs)
        self._check_refusal(response)
        return response

    def stream(self, *, system: str, user: str, max_tokens: int = 4096) -> Iterator[str]:
        with self._mapped_errors():
            with self._client.messages.stream(
                model=self._model,
                max_tokens=max_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": user}],
            ) as stream:
                for text in stream.text_stream:
                    yield text
                self._check_refusal(stream.get_final_message())

    @staticmethod
    def _text(response: anthropic.types.Message) -> str:
        return "".join(block.text for block in response.content if block.type == "text").strip()

    def complete(self, *, system: str, user: str, max_tokens: int = 4096) -> LlmReply:
        response = self._create(
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
        )
        return LlmReply(self._text(response), response.usage.input_tokens, response.usage.output_tokens)

    def complete_json(self, *, system: str, user: str, schema: dict[str, Any], max_tokens: int = 8192) -> dict[str, Any]:
        response = self._create(
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        try:
            return json.loads(self._text(response))
        except json.JSONDecodeError as exc:
            raise LlmError("bad_output", "The model returned something that wasn't valid JSON.", 502) from exc
