from fastapi import FastAPI, Header, HTTPException
from app.rules import analyze_message
from app.client import explain_scam
from app.database import init_db, save_message, save_intelligence, get_session_intelligence
from app.models import HoneypotRequest
from app.persona import generate_reply_ai
import os
from dotenv import load_dotenv
load_dotenv()
app = FastAPI(title="Agentic Honeypot API")
API_KEY = os.getenv("HONEYPOT_API_KEY")
init_db()
print(API_KEY)
@app.get("/honeypot")
def health():
    return {"status": "running"}
@app.post("/honeypot")
def honeypot(req: HoneypotRequest,x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    analysis = analyze_message(req.message)
    explanation = explain_scam(req.message)
    is_scam = explanation.strip().lower().startswith("spam")
    if is_scam:
        a = 1
    else:
        a = 0
    save_message(req.session_id, "scammer", req.message,a)
    scam_type = "None"
    if is_scam:
        try:
            scam_type = explanation.split(":")[0].replace("Spam -", "").strip()
        except:
            scam_type = "Other"

    for upi in analysis["upi_ids"]:
        save_intelligence(
            req.session_id,
            upi_id=upi,
            bank_account=None,
            ifsc_code=None,
            phishing_link=None
        )

    # Save bank accounts
    for acc in analysis["bank_accounts"]:
        save_intelligence(
            req.session_id,
            upi_id=None,
            bank_account=acc,
            ifsc_code=None,
            phishing_link=None
        )

    # Save IFSC codes
    for ifsc in analysis["ifsc_codes"]:
        save_intelligence(
            req.session_id,
            upi_id=None,
            bank_account=None,
            ifsc_code=ifsc,
            phishing_link=None
        )

    # Save phishing links
    for link in analysis["phishing_links"]:
        save_intelligence(
            req.session_id,
            upi_id=None,
            bank_account=None,
            ifsc_code=None,
            phishing_link=link["url"]
        )
    persona_reply = None
    if is_scam:
        persona_reply = generate_reply_ai(
            req.message,
            req.session_id
        )
    confidence = min(0.95, 0.4 + analysis["score"] * 0.15)
    session_intel = get_session_intelligence(req.session_id)
    return {
        "session_id": req.session_id,
        "scam_detected": is_scam,
        "scam_type":  scam_type if is_scam else "None",
        "confidence": round(confidence, 2),
        "risk_level": "HIGH" if is_scam else "LOW",
        "extracted_intelligence": session_intel,
        "conversation_summary": explanation,
        "persona_reply": persona_reply
    }


