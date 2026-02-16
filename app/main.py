from fastapi import FastAPI, Header, HTTPException, Request
from app.models import HoneypotRequest
from app.rules import analyze_message
from app.persona import generate_persona_reply, explain_scam
from app.database import init_db, save_intelligence, get_session_intelligence
from app.callback import send_final_result
from app.duration import calculate_engagement_duration
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
async def honeypot(req: Request,x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        try:
            data = await req.json()
        except:
            return {
                "status": "success",
                "reply": "Hello, could you repeat that?"
            }

        session_id = data.get("sessionId", "unknown")

        message_obj = data.get("message", {})
        message = message_obj.get("text", "")

        history = data.get("conversationHistory", [])
        analysis = analyze_message(message)

        for u in analysis["upi_ids"]:
            save_intelligence(session_id, upi=u)

        for b in analysis["bank_accounts"]:
            save_intelligence(session_id, bank=b)

        for i in analysis["ifsc_codes"]:
            save_intelligence(session_id, ifsc=i)

        for l in analysis["phishing_links"]:
            if isinstance(l, tuple):
                l = l[0]
            save_intelligence(session_id, link=l)

        for p in analysis["phone_numbers"]:
            save_intelligence(session_id, phone=p)

        for e in analysis["emailAddresses"]:
            save_intelligence(session_id, email=e)

        for k in analysis["keywords"]:
            save_intelligence(session_id, keyword=k)
            
        history_text = ""
        for msg in history:
            sender = "unknown"
            text = ""
            if isinstance(msg, dict):
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
            else:
                sender = msg.sender
                text = msg.text
            history_text += f"{sender}: {text}\n"
        reply = generate_persona_reply(message, history_text)
        explanation = explain_scam(message)
        is_scam = explanation.strip().lower().startswith("spam")
        scam_type = "None"
        tactics = "None"
        parts = explanation.split(":")
        if is_scam:
            if len(parts) >= 2:
                scam_type = parts[0].replace("Spam -", "").strip()
            if len(parts) >= 3:
                tactics = parts[2].strip()
        else:
            if len(parts) >= 3:
                tactics = parts[2].strip()
        total_messages = len(history) + 1
        MIN_TURNS = 19
        intel = get_session_intelligence(session_id)
        intel_types = sum([
            bool(intel["upi_ids"]),
            bool(intel["bank_accounts"]),
            bool(intel["phishing_links"]),
            bool(intel["phone_numbers"]),
            bool(intel["ifsc_codes"])
        ])
        final_is_scam = is_scam or intel_types > 0
        engagement_duration = calculate_engagement_duration(data)
        FINAL_SENT = set()
        if intel_types >= 3:
            should_end = True
        elif intel_types >= 2 and total_messages//2 >= 7:
            should_end = True
        elif total_messages > MIN_TURNS:
            should_end = True
        else:
            should_end = False

        if session_id not in FINAL_SENT and should_end:
            send_final_result(
                session_id=session_id,
                is_scam=final_is_scam,
                scam_type=scam_type,
                tactics=tactics,
                intelligence=intel,
                total_messages=total_messages//2,
                engagement_duration = engagement_duration
            )
             FINAL_SENT.add(session_id)
        return {
            "status": "success",
            "reply": reply or "Okay, can you explain more?"
        }
    except Exception as e:
        print("ERROR:", str(e))
        return {
            "status": "success",
            "reply": "I'm not sure I understood. Can you explain again?"
        }












