from fastapi import FastAPI, Header, HTTPException
from app2.models import HoneypotRequest
from app2.rules import analyze_message
from app2.persona import generate_persona_reply, explain_scam
from app2.database import init_db, save_intelligence
from app2.callback import send_final_result
import os
from dotenv import load_dotenv
load_dotenv()
app = FastAPI()
init_db()

API_KEY = os.getenv("HONEYPOT_API_KEY")

@app.api_route("/", methods=["GET", "HEAD"])
def health():
    return {"status": "running"}

@app.post("/")
def honeypot(req: HoneypotRequest,x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    session_id = req.sessionId
    message = req.message.text


    # Analyze scam message
    analysis = analyze_message(message)

    # Save intelligence
    for u in analysis["upi_ids"]:
        save_intelligence(session_id, upi=u)

    for b in analysis["bank_accounts"]:
        save_intelligence(session_id, bank=b)

    for i in analysis["ifsc_codes"]:
        save_intelligence(session_id, ifsc=i)

    for l in analysis["phishing_links"]:
        save_intelligence(session_id, link=l)

    # Build history text
    history_text = ""
    for msg in req.conversationHistory:
        history_text += f"{msg.sender}: {msg.text}\n"

    # Generate persona reply
    reply = generate_persona_reply(message, history_text)
    explanation = explain_scam(message)
    is_scam = explanation.strip().lower().startswith("spam")
    scam_type = explanation.split(":")[0].replace("Spam -", "").strip()
    tactics = explanation.split(":")[2]
        # Count messages
    total_messages = len(req.conversationHistory) + 1
    MIN_TURNS = 15
    # Check if intelligence exists
    intelligence_found = (
        analysis["upi_ids"]
        and analysis["bank_accounts"]
        and analysis["phishing_links"]
        and analysis["phone_numbers"]
    )

    print(intelligence_found)

    if intelligence_found or total_messages >= MIN_TURNS:
        send_final_result(
            session_id=session_id,
            is_scam=is_scam,
            scam_type=scam_type,
            tactics=tactics,
            intelligence=analysis,
            total_messages=total_messages
        )



    # IMPORTANT: required response format
    return {
        "status": "success",
        "reply": reply
    }
