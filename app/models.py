from pydantic import BaseModel
from typing import Optional
class HoneypotRequest(BaseModel):
    message: str
    session_id: Optional[str] = "default"
