from fastapi import FastAPI, Header, HTTPException, Request
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
@app.api_route("/", methods=["GET", "HEAD"])
def health():
    return {"status": "running"}

@app.post("/")
async def honeypot(req: Request, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        data = await req.json()
        session_id = data.get("sessionId", "unknown")
        message = data.get("message", {}).get("text", "")
        history = data.get("conversationHistory", [])

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
        for p in analysis["phone_numbers"]:
            save_intelligence(session_id, phone=p)
        for e in analysis["emailAddresses"]:
            save_intelligence(session_id, email=e)
        for k in analysis["keywords"]:
            save_intelligence(session_id, keyword=k)

        # Build history text
        history_text = ""
        for msg in history:
            history_text += f"{msg.get('sender')}: {msg.get('text')}\n"

        reply = generate_persona_reply(message, history_text)

        explanation = explain_scam(message)
        is_scam = explanation.lower().startswith("spam")

        scam_type = "Unknown"
        tactics = "Unknown"

        parts = explanation.split(":")
        if is_scam and len(parts) >= 2:
            scam_type = parts[0].replace("Spam -", "").strip()
        if len(parts) >= 3:
            tactics = parts[2].strip()

        total_messages = len(history) + 1
        intel = get_session_intelligence(session_id)

        engagement_duration = total_messages * 5

        if total_messages >= 6:
            send_final_result(
                session_id=session_id,
                is_scam=is_scam,
                scam_type=scam_type,
                tactics=tactics,
                intelligence=intel,
                total_messages=total_messages,
                engagement_duration=engagement_duration
            )

        return {
            "status": "success",
            "reply": reply
        }

    except Exception:
        return {
            "status": "success",
            "reply": "Can you explain that again?"
        }

