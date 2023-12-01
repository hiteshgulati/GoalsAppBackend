import logging
import os
from functools import lru_cache

from pydantic import AnyUrl, BaseSettings

log = logging.getLogger("uvicorn")

class Settings(BaseSettings):
    environment: str = os.getenv("ENVIRONMENT", "dev")
    database_url: AnyUrl = os.environ.get("DATABASE_URL")
    name: str = "Goals App"
    version: str = "0.1.1"
    MSG91_AUTHKEY: str = os.environ.get("MSG91_AUTHKEY")
    MSG91_DOMAIN: str = "devmailer.embetter.in"
    MSG91_FROM_EMAIL: str = "no-reply@devmailer.embetter.in" 
    DB_CONN_STRING: str = "postgresql://admin:test@172.17.0.1:5433/postgres"

@lru_cache()
def get_settings() -> BaseSettings:
    log.info("Loading config settings from the environment...")
    return Settings()
