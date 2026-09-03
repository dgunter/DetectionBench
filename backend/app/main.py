from __future__ import annotations

import importlib.metadata
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import __version__
from app.api.auth import router as auth_router
from app.api.examples import router as examples_router
from app.api.llm import llm_error_handler, router as llm_router
from app.llm.client import LlmError
from app.api.classify import router as classify_router
from app.auth import request_is_authenticated
from app.config import get_settings
from app.pipeline.attack import load_attack_dataset

# Routes reachable without a session cookie. Everything else under /api/ needs one.
PUBLIC_PATHS = frozenset({
    "/api/health",
    "/api/auth/verify",
    "/api/auth/logout",
    "/api/auth/session",
})


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load bundled resources up front so a deploy that can't find them fails at boot,
    # not on the first request.
    app.state.attack = load_attack_dataset()
    app.state.ready = True
    yield


app = FastAPI(title="DetectionBench API", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
app.include_router(auth_router)
app.include_router(examples_router)
app.include_router(llm_router)
app.add_exception_handler(LlmError, llm_error_handler)
app.include_router(classify_router)


@app.middleware("http")
async def gate_and_size_cap(request: Request, call_next):
    settings = get_settings()
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_PATHS:
        if not request_is_authenticated(request, settings):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > settings.max_body_bytes:
        return JSONResponse({"detail": "request body too large (64 KB max)"}, status_code=413)
    return await call_next(request)


class Health(BaseModel):
    status: str
    version: str
    pysigma_version: str
    attack_dataset_version: str
    attack_technique_count: int


@app.get("/api/health", response_model=Health)
def health(request: Request) -> Health:
    attack = request.app.state.attack
    return Health(
        status="ok",
        version=__version__,
        pysigma_version=importlib.metadata.version("pysigma"),
        attack_dataset_version=attack.version,
        attack_technique_count=attack.technique_count,
    )
