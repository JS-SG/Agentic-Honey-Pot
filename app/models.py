from pydantic import BaseModel

class HoneypotRequest(BaseModel):
    message: str
    session_id: str