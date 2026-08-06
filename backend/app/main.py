from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import catalog, health

app = FastAPI(title="Internal Security Rating Platform - Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(catalog.router)

@app.get("/", tags=["root"])
async def root():
    return {"message": "SSC Backend"}
