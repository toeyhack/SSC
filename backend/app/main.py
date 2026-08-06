from fastapi import FastAPI
from app.api import health

app = FastAPI(title="Internal Security Rating Platform - Backend")

app.include_router(health.router, prefix="/health", tags=["health"])

@app.get("/", tags=["root"])
async def root():
    return {"message": "SSC Backend - Phase 0"}
