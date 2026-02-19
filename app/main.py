from fastapi import FastAPI, Header, HTTPException, Request
from app.rules import analyze_message
from app.persona import generate_persona_reply, explain_scam
from app.database import init_db, save_intelligence, get_session_intelligence, update_session_status, get_session_status, mark_callback_sent
from app.callback import send_final_result
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
load_dotenv()
app = FastAPI()
init_db()

API_KEY = os.getenv("HONEYPOT_API_KEY")

@app.api_route("/", methods=["GET", "HEAD"])
def health():
    return {"status": "running"}


def parse_timestamp(ts):
    if isinstance(ts, int) or (isinstance(ts, str) and ts.isdigit()):
        return int(ts) / 1000

    if isinstance(ts, str):
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()

    return None


def calculate_engagement_duration(request_data):
    timestamps = []

    msg_ts = request_data.get("message", {}).get("timestamp")
    if msg_ts:
        parsed = parse_timestamp(msg_ts)
        if parsed is not None:
            timestamps.append(parsed)

    for msg in request_data.get("conversationHistory", []):
        ts = msg.get("timestamp")
        if ts:
            parsed = parse_timestamp(ts)
            if parsed is not None:
                timestamps.append(parsed)

    if not timestamps:
        return 0
    return int(max(timestamps) - min(timestamps))


@app.post("/")
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
        intel = get_session_intelligence(session_id)
        intel_types = sum([
            bool(intel["upiIds"]),
            bool(intel["bankAccounts"]),
            bool(intel["phishingLinks"]),
            bool(intel["phoneNumbers"]),
            bool(intel["emailAddresses"])
        ])
        final_is_scam = is_scam or intel_types > 0
        engagement_duration = calculate_engagement_duration(data)
        update_session_status(
            session_id, 
            final_is_scam, 
            scam_type, 
            tactics, 
            engagement_duration, 
            total_messages
        )
        status = get_session_status(session_id)
        if (final_is_scam and total_messages//2 >= 5 and intel_types >= 2 and not status["callback_sent"]):
            send_final_result(
                session_id=session_id,
                is_scam=status["is_scam"],
                scam_type=status["scam_type"],
                tactics=status["tactics"],
                intelligence=intel,
                total_messages=status["message_count"],
                engagement_duration=status["engagement_duration"]
            )
            mark_callback_sent(session_id)
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

@app.get("/results/{session_id}")
def get_results(session_id: str):
    intel = get_session_intelligence(session_id)
    status = get_session_status(session_id)
    
    if not status:
        return {"error": "Session not found"}
        
    return {
        "status": "completed",
        "scamDetected": status["is_scam"],
        "scamType": status["scam_type"],
        "extractedIntelligence": intel,
        "engagementMetrics": {
            "totalMessagesExchanged": status["message_count"],
            "engagementDurationSeconds": status["engagement_duration"]
        },
        "agentNotes": f"Tactics identified: {status['tactics']}"
    }









