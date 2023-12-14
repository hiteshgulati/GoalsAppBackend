import logging
import os
from functools import lru_cache

from pydantic import AnyUrl, BaseSettings

log = logging.getLogger("uvicorn")

class Settings(BaseSettings):
    environment: str = os.getenv("ENVIRONMENT", "dev")
    database_url: AnyUrl = os.environ.get("DATABASE_URL")
    name: str = "Goals App"
    version: str = "0.1.3"
    MSG91_AUTHKEY: str = os.environ.get("MSG91_AUTHKEY")
    MSG91_DOMAIN: str = "devmailer.embetter.in"
    MSG91_FROM_EMAIL: str = "no-reply@devmailer.embetter.in" 
    DB_CONN_STRING: str = "postgresql://admin:test@172.17.0.1:5433/postgres"
    APPROVED_ISD_CODES: str = os.getenv("APPROVED_ISD_CODES", "91")
    JWT_SECRET_KEY:str = os.getenv("JWT_SECRET_KEY", "c05abfd605ae50561b407d0090c24c95b17fce2cd473367fd1fef89721fb76cf")
@lru_cache()
def get_settings() -> BaseSettings:
    log.info("Loading config settings from the environment...")
    return Settings()
