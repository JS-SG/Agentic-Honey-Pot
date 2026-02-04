from pydantic import BaseModel
from typing import List, Optional

class MessageInput(BaseModel):
    message: str
    session_id: str

class ScamResult(BaseModel):
    scam_detected: bool
    confidence: float
    reason: str

class Intelligence(BaseModel):
    upi_ids: List[str] = []
    bank_accounts: List[str] = []
    ifsc_codes: List[str] = []
    phishing_links: List[str] = []

class FinalResponse(BaseModel):
    scam_detected: bool
    scam_type: str
    confidence: float
    extracted_intelligence: Intelligence
    conversation_summary: str
    risk_level: str
