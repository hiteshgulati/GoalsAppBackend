import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.users import router as users_router
from config import Settings
from utils.db import init_db

log = logging.getLogger("uvicorn")

whitelisted_origins = [
    "http://amb-dev.embetter.in",
    "https://amb-dev.embetter.in",
    "http://ambition.fund",
    "https://ambition.fund",
    "http://dev.ambition.fund",
    "https://dev.ambition.fund",
    "http://localhost",
    "http://localhost:3000",
]

def create_application(whitelisted_origins) -> FastAPI:
    settings = Settings()
    application = FastAPI(title=settings.name, version=settings.version)
    application.include_router(users_router, prefix="/users")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=whitelisted_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return application

app = create_application(whitelisted_origins)

@app.on_event("startup")
async def startup_event():
    log.info("Starting up...")
    init_db()

@app.on_event("shutdown")
async def shutdown_event():
    log.info("Shutting down...")
