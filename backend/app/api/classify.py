"""POST /api/classify: the deterministic pipeline, stateless, one rule at a time.

A parse failure is a *result* (``ok: false`` with a structured error), not an
HTTP error: the UI renders it in the Parsed structure card and puts the other cards
into a waiting state. Only transport-level problems (auth, oversize body,
malformed JSON) use HTTP status codes.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.pipeline.attack import load_attack_dataset
from app.pipeline.attack_map import map_attack_tags
from app.pipeline.lint import lint_rule
from app.pipeline.parse import MAX_RULE_BYTES, ParseError, parse_rule
from app.pipeline.pyramid import classify as classify_pyramid
from app.pipeline.scope import describe

router = APIRouter(prefix="/api", tags=["classify"])


class ClassifyRequest(BaseModel):
    rule: str = Field(min_length=1, max_length=MAX_RULE_BYTES)


def run_pipeline(rule_text: str) -> dict[str, Any]:
    """Run every deterministic stage; shared with the LLM candidate re-scoring later on."""
    try:
        parsed = parse_rule(rule_text)
    except ParseError as exc:
        return {"ok": False, "error": exc.to_dict(), "structure": None, "scope": None, "pyramid": None, "lint": None, "attack": None}

    ir = parsed.ir
    dataset = load_attack_dataset()
    return {
        "ok": True,
        "error": None,
        "structure": {
            "value": ir.condition,
            "confidence": "high",
            "provenance": "deterministic:static",
            "rationale": "Condition tree as resolved by pySigma, with each selection expanded into its field tests.",
            "condition": ir.condition,
            "selections": list(ir.selections),
            "root": ir.root.to_dict(),
            "metadata": ir.metadata.to_dict(),
            "metadata_errors": [{"type": type(e).__name__, "message": str(e)} for e in parsed.metadata_errors],
        },
        "scope": describe(ir).to_dict(),
        "pyramid": classify_pyramid(ir).to_dict(),
        "lint": lint_rule(parsed.raw, ir, list(parsed.rule.detection.detections), parsed.metadata_errors, dataset).to_dict(),
        "attack": map_attack_tags(ir.metadata.tags, dataset).to_dict(),
    }


@router.post("/classify")
def classify(body: ClassifyRequest) -> dict[str, Any]:
    return run_pipeline(body.rule)
