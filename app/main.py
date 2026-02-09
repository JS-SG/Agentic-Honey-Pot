from fastapi import FastAPI, Header, HTTPException
from app.models import HoneypotRequest
from app.rules import analyze_message
from app.persona import generate_persona_reply, explain_scam
from app.database import init_db, save_intelligence, get_session_intelligence
from app.callback import send_final_result
import os
from dotenv import load_dotenv
load_dotenv()
app = FastAPI()
init_db()

API_KEY = os.getenv("HONEYPOT_API_KEY")

@app.api_route("/honeypot", methods=["GET", "HEAD"])
def health():
    return {"status": "running"}

@app.post("/honeypot")
def honeypot(req: HoneypotRequest,x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    session_id = req.sessionId
    message = req.message.text
    analysis = analyze_message(message)
    for u in analysis["upi_ids"]:
        save_intelligence(session_id, upi=u)

    for b in analysis["bank_accounts"]:
        save_intelligence(session_id, bank=b)

    for i in analysis["ifsc_codes"]:
        save_intelligence(session_id, ifsc=i)

    for l in analysis["phishing_links"]:
        save_intelligence(session_id, link=l)
    
    for p in analysis["phone_numbers"]:
        save_intelligence(session_id, phone=p)

    for k in analysis["keywords"]:
        save_intelligence(session_id, keyword=k)

    history_text = ""
    for msg in req.conversationHistory:
        history_text += f"{msg.sender}: {msg.text}\n"

    # Generate persona reply
    reply = generate_persona_reply(message, history_text)
    explanation = explain_scam(message)
    is_scam = explanation.strip().lower().startswith("spam")
    scam_type = explanation.split(":")[0].replace("Spam -", "").strip()
    tactics = explanation.split(":")[2]
    total_messages = len(req.conversationHistory) + 1
    MIN_TURNS = 19
    intel = get_session_intelligence(session_id)
    intel_types = sum([
        bool(intel["upi_ids"]),
        bool(intel["bank_accounts"]),
        bool(intel["phishing_links"]),
        bool(intel["phone_numbers"])
    ])

    if intel_types>=3 or total_messages >= MIN_TURNS:
        send_final_result(
            session_id=session_id,
            is_scam=is_scam,
            scam_type=scam_type,
            tactics=tactics,
            intelligence=intel,
            total_messages=total_messages
        )

    return {
        "status": "success",
        "reply": reply
    }






