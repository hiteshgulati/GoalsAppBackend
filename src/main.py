import logging

from fastapi import FastAPI

from api.users import router as users_router
from config import Settings
from utils.db import init_db

log = logging.getLogger("uvicorn")

def create_application() -> FastAPI:
    settings = Settings()
    application = FastAPI(title=settings.name, version=settings.version)
    application.include_router(users_router, prefix="/users")
    return application

app = create_application()

@app.on_event("startup")
async def startup_event():
    log.info("Starting up...")
    init_db()

@app.on_event("shutdown")
async def shutdown_event():
    log.info("Shutting down...")
