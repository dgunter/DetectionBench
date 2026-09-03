"""Re-score model-proposed candidate rules through our own pipeline.

AI proposes, verifiable logic checks: a candidate that fails to parse or
regresses is shown as such and never presented as a trusted suggestion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from app.llm.scoring import Scorer, ScoreSummary, summarize

MAX_CANDIDATE_BYTES = 64 * 1024

Verdict = Literal["raised", "preserved", "regressed", "parse_failed"]


@dataclass(frozen=True)
class CandidateResult:
    index: int
    strategy: str
    yaml: str
    verdict: Verdict
    label: str
    score: ScoreSummary
    tier_delta: int | None
    lint_error_delta: int | None
    lint_warning_delta: int | None

    @property
    def is_win(self) -> bool:
        return self.verdict in ("raised", "preserved")

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "strategy": self.strategy,
            "yaml": self.yaml,
            "verdict": self.verdict,
            "label": self.label,
            "is_win": self.is_win,
            "score": self.score.to_dict(),
            "tier_delta": self.tier_delta,
            "lint_error_delta": self.lint_error_delta,
            "lint_warning_delta": self.lint_warning_delta,
        }


def _delta(after: int | None, before: int | None) -> int | None:
    if after is None or before is None:
        return None
    return after - before


def judge(original: ScoreSummary, candidate: ScoreSummary) -> tuple[Verdict, str]:
    if not candidate.ok:
        return "parse_failed", f"Discarded: candidate doesn't parse ({candidate.parse_error or 'unknown error'})."
    if original.tier is not None and candidate.tier is not None:
        if candidate.tier < original.tier:
            return "regressed", f"Regressed: tier dropped from {original.tier_name} to {candidate.tier_name}."
        if candidate.lint_errors is not None and original.lint_errors is not None and candidate.lint_errors > original.lint_errors:
            return "regressed", "Regressed: introduces new lint errors."
        if candidate.tier > original.tier:
            return "raised", f"Tier raised: {original.tier_name} → {candidate.tier_name}."
    lint_note = ""
    if candidate.lint_errors == 0 and candidate.lint_errors is not None:
        lint_note = ", lint clean"
    return "preserved", f"Tier preserved{lint_note}. Fewer false positives is the win here."


def rescore(original_rule: str, proposals: list[dict[str, Any]], scorer: Scorer) -> dict[str, Any]:
    original = summarize(scorer(original_rule))
    results: list[CandidateResult] = []
    for i, proposal in enumerate(proposals):
        text = str(proposal.get("yaml", ""))
        strategy = str(proposal.get("strategy", "")).strip()
        if not text.strip() or len(text.encode("utf-8")) > MAX_CANDIDATE_BYTES:
            score = ScoreSummary(ok=False, parse_error="empty or oversized candidate")
        else:
            score = summarize(scorer(text))
        verdict, label = judge(original, score)
        results.append(
            CandidateResult(
                index=i,
                strategy=strategy,
                yaml=text,
                verdict=verdict,
                label=label,
                score=score,
                tier_delta=_delta(score.tier, original.tier),
                lint_error_delta=_delta(score.lint_errors, original.lint_errors),
                lint_warning_delta=_delta(score.lint_warnings, original.lint_warnings),
            )
        )
    return {"original": original.to_dict(), "candidates": [r.to_dict() for r in results]}
