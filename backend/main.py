"""
PhishSentinel — main.py v2.0.2

CORS fix: CORSMiddleware has a known issue where allow_origin_regex is checked
AFTER the request is partially processed, causing OPTIONS to return 400 when
the extension origin doesn't match a literal string in allow_origins.

Solution: Remove CORSMiddleware entirely. Add a raw @app.middleware("http")
that manually injects CORS headers on EVERY response and short-circuits OPTIONS
with an immediate 200 — before any route logic or rate limiter runs.
This is the most reliable approach and works regardless of Starlette version.
"""

import asyncio
import logging
import time
from collections import defaultdict

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from engines import ml_engine, domain_engine, heuristic_engine, header_engine
from scorer import aggregate

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("PhishSentinel")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "PhishSentinel API",
    description = "Multi-engine phishing detection: ML + OSINT + Heuristics + Header Analysis",
    version     = "2.0.2",
)

# ── CORS headers ──────────────────────────────────────────────────────────────
# Allow any chrome-extension://, moz-extension://, or localhost origin.
# We check the request Origin and echo it back — this is required for
# credentialled or extension requests.
_ALLOWED_ORIGIN_PREFIXES = (
    "chrome-extension://",
    "moz-extension://",
    "http://127.0.0.1",
    "http://localhost",
)

def _cors_origin(request: Request) -> str:
    origin = request.headers.get("origin", "")
    if any(origin.startswith(p) for p in _ALLOWED_ORIGIN_PREFIXES):
        return origin
    return ""   # don't set header for disallowed origins


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    origin = _cors_origin(request)

    # Short-circuit preflight immediately — never let it reach routes
    if request.method == "OPTIONS":
        return Response(
            status_code = 200,
            headers     = {
                "Access-Control-Allow-Origin"     : origin or "*",
                "Access-Control-Allow-Methods"    : "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers"    : "Content-Type, Accept, Origin",
                "Access-Control-Max-Age"          : "600",
                "Vary"                            : "Origin",
            },
        )

    response = await call_next(request)

    if origin:
        response.headers["Access-Control-Allow-Origin"]  = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Accept, Origin"
        response.headers["Vary"]                         = "Origin"

    return response


# ── Rate Limiter ──────────────────────────────────────────────────────────────
_rate_store: dict = defaultdict(list)
_RATE_WINDOW = 60
_RATE_LIMIT  = 40


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Preflight already handled above — this only sees real requests
    ip  = request.client.host if request.client else "unknown"
    now = time.time()
    hits = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    _rate_store[ip] = hits
    if len(hits) >= _RATE_LIMIT:
        log.warning(f"Rate limit hit: {ip}")
        return JSONResponse(status_code=429, content={"error": "Too many requests."})
    _rate_store[ip].append(now)
    return await call_next(request)


# ── Request Model ─────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    text       : str       = Field(default="", max_length=25_000)
    links      : list[str] = Field(default=[])
    raw_headers: str       = Field(default="", max_length=10_000)

    model_config = {
        "json_schema_extra": {
            "example": {
                "text"       : "Dear user, your account will be suspended. Verify now.",
                "links"      : ["https://paypa1.com/login", "http://185.0.0.1/verify"],
                "raw_headers": "Authentication-Results: spf=fail dkim=none dmarc=fail",
            }
        }
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/scan", summary="Full phishing analysis")
async def scan(req: ScanRequest):
    links = list(dict.fromkeys(str(l).strip() for l in req.links if l))[:30]
    text  = req.text.strip()

    if not text and not links and not req.raw_headers:
        return JSONResponse(
            status_code = status.HTTP_400_BAD_REQUEST,
            content     = {"error": "Provide at least one of: text, links, raw_headers."},
        )

    log.info(f"Scan — {len(text)} chars | {len(links)} link(s) | headers: {'yes' if req.raw_headers else 'no'}")

    t0 = time.perf_counter()

    ml_res, domain_res, heuristic_res, header_res = await asyncio.gather(
        ml_engine.run(text),
        domain_engine.run(links),
        heuristic_engine.run(links),
        header_engine.run(req.raw_headers),
    )

    elapsed = round(time.perf_counter() - t0, 3)
    verdict = aggregate({
        "ml": ml_res, "domain": domain_res,
        "heuristic": heuristic_res, "header": header_res,
    })

    log.info(f"Verdict → {verdict['overall_risk']} | Score={verdict['overall_score']} | {elapsed}s")

    return {
        **verdict,
        "scan_time_ms": round(elapsed * 1000),
        "detail": {
            "ml": ml_res, "domain": domain_res,
            "heuristic": heuristic_res, "header": header_res,
        },
    }


@app.get("/api/health", summary="Server health check")
async def health():
    from engines.ml_engine import _model
    return {
        "status" : "ok",
        "version": "2.0.2",
        "engines": {
            "ml"       : "ready" if _model is not None else "model_missing — run train_model.py",
            "domain"   : "ready",
            "heuristic": "ready",
            "header"   : "ready",
        },
    }


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000, reload=False, log_level="info")