from __future__ import annotations

import json
import time
from functools import lru_cache
from typing import Any, Iterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.auth import client_ip
from app.config import get_settings
from app.llm.candidates import rescore
from app.llm.client import MODEL_KEYS, AnthropicLlmClient, LlmClient, LlmError, resolve_model
from app.llm.prompts import attack_schema, candidates_prompt, candidates_schema, explain_prompt, suggest_attack_prompt
from app.llm.scoring import Scorer, analysis_context, default_scorer
from app.pipeline.attack import load_attack_dataset
from app.ratelimit import GlobalBudget, SlidingWindow

router = APIRouter(prefix="/api/llm", tags=["llm"])

_settings = get_settings()
ip_limiter = SlidingWindow(_settings.llm_rate_limit, _settings.llm_rate_window_seconds)
hourly_budget = GlobalBudget(_settings.llm_hourly_budget, 3600)


class LlmRequest(BaseModel):
    rule: str = Field(min_length=1, max_length=64 * 1024)
    model: str = Field(default="opus", max_length=16)


@lru_cache(maxsize=1)
def _anthropic_client() -> AnthropicLlmClient | None:
    settings = get_settings()
    if not settings.anthropic_api_key:
        return None
    return AnthropicLlmClient(settings.anthropic_api_key, settings.llm_model, settings.llm_timeout_seconds)


def get_llm_client() -> LlmClient:
    client = _anthropic_client()
    if client is None:
        raise LlmError("not_configured", "The AI panel isn't configured on this server.", 503)
    return client


def get_scorer() -> Scorer | None:
    return default_scorer()


def _guard(request: Request, body: LlmRequest) -> str:
    """Validate the model key and the limits; return the resolved model ID for the call."""
    model = resolve_model(get_settings(), body.model)
    if not ip_limiter.allow(client_ip(request)):
        raise LlmError("rate_limited", "Too many AI requests from your address. Wait a minute.", 429)
    if not hourly_budget.allow():
        raise LlmError("budget_exhausted", "The shared hourly AI budget is used up. Try again later.", 429)
    return model


def _analysis(scorer: Scorer | None, rule: str) -> dict[str, Any] | None:
    if scorer is None:
        return None
    return analysis_context(scorer(rule))


def _envelope(action: str, body: LlmRequest, **payload: Any) -> dict[str, Any]:
    return {"action": action, "model": body.model, "provenance": "inferred:llm", "confidence": "low", **payload}


@router.get("/models")
def models() -> list[dict[str, Any]]:
    return [{"key": key, "enabled": model_id is not None} for key, model_id in MODEL_KEYS.items()]


@router.get("/budget")
def budget() -> dict[str, int]:
    return {"remaining": hourly_budget.remaining(), "limit": hourly_budget.limit}


@router.post("/explain")
def explain(body: LlmRequest, request: Request, client: LlmClient = Depends(get_llm_client), scorer: Scorer | None = Depends(get_scorer)) -> dict[str, Any]:
    model = _guard(request, body)
    reply = client.complete(model=model, system=_system(), user=explain_prompt(body.rule, _analysis(scorer, body.rule)))
    return _envelope("explain", body, text=reply.text)


def _sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}\n\n"


def _wall_clock_limit() -> float:
    return get_settings().llm_timeout_seconds


@router.post("/explain/stream")
def explain_stream(body: LlmRequest, request: Request, client: LlmClient = Depends(get_llm_client), scorer: Scorer | None = Depends(get_scorer)) -> StreamingResponse:
    """Server-sent events: {"type":"delta","text"} ... then {"type":"done"} or {"type":"error","code","message"}.

    Limits and model gating are checked before the stream opens, so those still
    fail with a normal HTTP status; anything that goes wrong after the first
    byte is reported as an error event on the stream.
    """
    model = _guard(request, body)
    prompt = explain_prompt(body.rule, _analysis(scorer, body.rule))
    system = _system()

    def events() -> Iterator[str]:
        started = time.monotonic()
        limit = _wall_clock_limit()
        try:
            for delta in client.stream(model=model, system=system, user=prompt):
                if time.monotonic() - started > limit:
                    yield _sse({"type": "error", "code": "timeout", "message": "The model took too long to answer. Try again."})
                    return
                yield _sse({"type": "delta", "text": delta})
            yield _sse({"type": "done", "model": body.model, "provenance": "inferred:llm"})
        except LlmError as exc:
            yield _sse({"type": "error", **exc.to_dict()})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/suggest-attack")
def suggest_attack(body: LlmRequest, request: Request, client: LlmClient = Depends(get_llm_client), scorer: Scorer | None = Depends(get_scorer)) -> dict[str, Any]:
    model = _guard(request, body)
    data = client.complete_json(model=model, system=_system(), user=suggest_attack_prompt(body.rule, _analysis(scorer, body.rule)), schema=attack_schema())
    dataset = load_attack_dataset()
    suggestions = []
    for item in data.get("techniques", [])[:6]:
        technique_id = str(item.get("id", "")).strip().upper()
        known = dataset.get(technique_id)
        if known is None:
            status = "unknown"
        elif known.retired:
            status = "retired"
        else:
            status = "valid"
        suggestions.append(
            {
                "id": technique_id,
                "name": known.name if known else str(item.get("name", "")),
                "url": known.url if known else None,
                "status": status,
                "replaced_by": known.revoked_by if known else None,
                "rationale": str(item.get("rationale", "")),
                "confidence": item.get("confidence", "low"),
                "already_declared": bool(item.get("already_declared")),
            }
        )
    return _envelope("suggest_attack", body, suggestions=suggestions, dataset_version=dataset.version)


@router.post("/candidates")
def candidates(body: LlmRequest, request: Request, client: LlmClient = Depends(get_llm_client), scorer: Scorer | None = Depends(get_scorer)) -> dict[str, Any]:
    model = _guard(request, body)
    if scorer is None:
        raise LlmError("rescoring_unavailable", "Candidate re-scoring isn't available on this server.", 503)
    settings = get_settings()
    data = client.complete_json(
        model=model,
        system=_system(),
        user=candidates_prompt(body.rule, _analysis(scorer, body.rule)),
        schema=candidates_schema(),
        effort=settings.llm_candidates_effort,
        timeout=settings.llm_candidates_timeout_seconds,
    )
    proposals = list(data.get("candidates", []))[:3]
    return _envelope("candidates", body, **rescore(body.rule, proposals, scorer))


def _system() -> str:
    from app.llm.prompts import SYSTEM

    return SYSTEM


def llm_error_handler(_: Request, exc: LlmError) -> JSONResponse:
    return JSONResponse({"detail": exc.message, "error": exc.to_dict()}, status_code=exc.http_status)
