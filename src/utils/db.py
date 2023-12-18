from sqlmodel import create_engine, SQLModel
from config import Settings

settings = Settings()
engine = create_engine(settings.DB_CONN_STRING)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_db():
    return engine
