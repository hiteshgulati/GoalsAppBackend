from pydantic import BaseModel


class StandardResponse(BaseModel):
    success: bool
    message: str
