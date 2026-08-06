from fastapi import APIRouter
from starlette.responses import JSONResponse
import os
import asyncio

router = APIRouter()

@router.get("/ping")
async def ping():
    return {"status": "ok"}

@router.get("/service")
async def service_health():
    return {"status": "ok", "service": "backend"}

@router.get("/db")
async def db_health():
    from app.db.session import engine
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "db": "reachable"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})

@router.get("/redis")
async def redis_health():
    import redis
    from app.core.config import settings
    try:
        r = redis.from_url(settings.REDIS_URL)
        r.ping()
        return {"status": "ok", "redis": "reachable"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})
