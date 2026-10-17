"""
app.py — PhishGuard AI API (FastAPI).

  POST /predict_url   {"url": "..."}  -> verdict, risk score, reasons
  GET  /stats                         -> dashboard numbers
  GET  /recent?limit=20               -> latest scans
  GET  /health                        -> status + blocklist feed status

Run:  uvicorn app:app --reload
"""

import os
import threading
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database
import predict

FEED_REFRESH_HOURS = 6
RATE_LIMIT_PER_MIN = 120   # /predict_url calls per client IP per minute

_hits = {}                 # ip -> timestamps of recent calls
_hits_lock = threading.Lock()


def _allowed(ip: str) -> bool:
    now = time.time()
    with _hits_lock:
        if len(_hits) > 10_000:   # forget idle clients so memory stays bounded
            for k in [k for k, q in _hits.items() if not q or now - q[-1] > 60]:
                del _hits[k]
        q = _hits.setdefault(ip, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MIN:
            return False
        q.append(now)
        return True


def _client_ip(request: Request) -> str:
    # Behind Render's proxy the real client is the first X-Forwarded-For entry
    # (best effort: a client can fake this header, so it's a speed bump, not security).
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


def _feed_loop():
    while True:
        added = predict.refresh_feed()
        print(f"[PhishGuard] OpenPhish feed: {added} new URLs, "
              f"{predict.feed_status['live_urls']} live total, error={predict.feed_status['last_error']}")
        time.sleep(FEED_REFRESH_HOURS * 3600)


@asynccontextmanager
async def lifespan(app):
    # Download the live OpenPhish feed now and every few hours, in the background
    # so startup isn't blocked. Set PHISHGUARD_FEED=off to disable (e.g. offline).
    if os.environ.get("PHISHGUARD_FEED", "on") != "off":
        threading.Thread(target=_feed_loop, daemon=True).start()
    yield


app = FastAPI(title="PhishGuard AI", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
                   allow_methods=["*"], allow_headers=["*"])


class URLRequest(BaseModel):
    url: str


@app.post("/predict_url")
def predict_url(req: URLRequest, request: Request):
    if not _allowed(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests, try again in a minute")
    start = time.perf_counter()
    try:
        verdict = predict.analyze(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        database.log_scan(verdict["domain"], verdict["result"], verdict["risk_score"],
                          time.perf_counter() - start)
    except Exception as e:   # logging must never break a verdict
        print(f"[PhishGuard] could not log scan: {e!r}")
    return verdict


@app.get("/stats")
def stats():
    return database.get_stats()


@app.get("/recent")
def recent(limit: int = 20):
    return database.get_recent(max(1, min(limit, 200)))


@app.get("/health")
def health():
    return {"status": "ok", "blocklist_urls": len(predict.BLOCKLIST), "feed": predict.feed_status}
