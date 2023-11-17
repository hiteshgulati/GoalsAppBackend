import logging
from fastapi import APIRouter

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

router = APIRouter()
