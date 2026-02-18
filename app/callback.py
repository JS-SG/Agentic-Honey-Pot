import requests

GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_result(session_id, is_scam, scam_type, tactics,
                      intelligence, total_messages, engagement_duration):

    payload = {
        "status": "success",
        "scamDetected": is_scam,
        "scamType": scam_type,
        "extractedIntelligence": intelligence,
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": engagement_duration
        },
        "agentNotes": f"{Tactics identified from scammer : {tactics}"
    }

    try:
        requests.post(GUVI_ENDPOINT, json=payload, timeout=5)
        print(payload)
        print("Status called")
    except Exception:
        pass
