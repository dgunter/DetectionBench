"""Bridge between the LLM panel and the deterministic pipeline.

The pipeline entry point lives in ``app.api.classify.run_pipeline``. It is
imported lazily so this package still imports (and its tests still run) on a
checkout where that module hasn't landed yet; in that case candidate
re-scoring reports itself unavailable rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

Scorer = Callable[[str], dict[str, Any]]


@dataclass(frozen=True)
class ScoreSummary:
    ok: bool
    tier: int | None = None
    tier_name: str | None = None
    confidence: str | None = None
    lint_errors: int | None = None
    lint_warnings: int | None = None
    parse_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "tier": self.tier,
            "tier_name": self.tier_name,
            "confidence": self.confidence,
            "lint_errors": self.lint_errors,
            "lint_warnings": self.lint_warnings,
            "parse_error": self.parse_error,
        }


def summarize(result: dict[str, Any]) -> ScoreSummary:
    """Reduce a full pipeline result to the numbers the panel compares."""
    if not result.get("ok"):
        err = result.get("error") or {}
        return ScoreSummary(ok=False, parse_error=err.get("message") if isinstance(err, dict) else str(err))
    pyramid = result.get("pyramid") or {}
    lint = result.get("lint") or {}
    findings = lint.get("findings") if isinstance(lint, dict) else None
    errors = warnings = None
    if isinstance(findings, list):
        errors = sum(1 for f in findings if f.get("severity") == "error")
        warnings = sum(1 for f in findings if f.get("severity") == "warning")
    return ScoreSummary(
        ok=True,
        tier=pyramid.get("tier"),
        tier_name=pyramid.get("value"),
        confidence=pyramid.get("confidence"),
        lint_errors=errors,
        lint_warnings=warnings,
    )


def analysis_context(result: dict[str, Any]) -> dict[str, Any] | None:
    """The slice of the deterministic result worth showing the model."""
    if not result.get("ok"):
        return None
    pyramid = result.get("pyramid") or {}
    scope = result.get("scope") or {}
    attack = result.get("attack") or {}
    return {
        "pyramid_tier": pyramid.get("tier"),
        "pyramid_tier_name": pyramid.get("value"),
        "pyramid_confidence": pyramid.get("confidence"),
        "pyramid_rationale": pyramid.get("rationale"),
        "categories": pyramid.get("categories"),
        "scope_summary": scope.get("summary"),
        "declared_techniques": [t.get("id") for t in attack.get("techniques", [])] if isinstance(attack, dict) else None,
    }


def default_scorer() -> Scorer | None:
    try:
        from app.api.classify import run_pipeline
    except ImportError:
        return None
    return run_pipeline
