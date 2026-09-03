from __future__ import annotations

from fastapi import APIRouter

from app.examples import load_examples

router = APIRouter(prefix="/api/examples", tags=["examples"])


@router.get("")
def list_examples() -> list[dict[str, str]]:
    return [e.to_dict() for e in load_examples()]
