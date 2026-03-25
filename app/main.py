"""FastAPI application factory — lifespan, WebSocket, health, exception handlers."""

import asyncio
import json
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from sqlalchemy import text

from app.config import settings
from app.database import engine
from app.routers import analysis, auth, nas, reports, tasks

ALGORITHM = "HS256"


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()


app = FastAPI(title="Suricata Web API", version="1.0.0", lifespan=lifespan)

# CORS
origins = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Include routers
app.include_router(auth.router)
app.include_router(nas.router)
app.include_router(tasks.router)
app.include_router(analysis.router)
app.include_router(reports.router)


# ── Unified exception handlers ──────────────────────────────────────────────


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "INTERNAL_ERROR", "message": str(exc.detail), "detail": None},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "INTERNAL_ERROR", "message": "伺服器內部錯誤", "detail": None},
    )


# ── Health check ─────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check():
    status_resp = {"status": "ok", "database": "ok", "redis": "ok", "nas_mount": "ok"}
    http_code = 200

    # Check database
    try:
        from app.database import async_session

        async with async_session() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        status_resp["database"] = "error"
        http_code = 503

    # Check Redis
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.aclose()
    except Exception:
        status_resp["redis"] = "error"
        http_code = 503

    # Check NAS mount
    from pathlib import Path

    if not Path(settings.NAS_MOUNT_PATH).is_dir():
        status_resp["nas_mount"] = "error"
        http_code = 503

    if http_code != 200:
        status_resp["status"] = "degraded"

    return JSONResponse(status_code=http_code, content=status_resp)


# ── WebSocket progress relay ─────────────────────────────────────────────────


@app.websocket("/ws/task/{task_id}")
async def ws_task_progress(websocket: WebSocket, task_id: str):
    # Validate JWT from query param
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001)
        return
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            await websocket.close(code=4001)
            return
    except JWTError:
        await websocket.close(code=4001)
        return

    await websocket.accept()

    # Subscribe to Redis pub/sub channel for this task
    r = aioredis.from_url(settings.REDIS_URL)
    pubsub = r.pubsub()
    channel = f"task:{task_id}:progress"
    await pubsub.subscribe(channel)

    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg["type"] == "message":
                data = json.loads(msg["data"])
                await websocket.send_json(data)
                if data.get("step") in ("done", "error"):
                    break
            else:
                # No message yet — send ping to keep connection alive
                try:
                    await websocket.send_json({"step": "ping", "progress": -1})
                except Exception:
                    break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await r.aclose()
        try:
            await websocket.close()
        except Exception:
            pass
