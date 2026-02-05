from pydantic import BaseModel
from typing import List, Optional

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[int] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
