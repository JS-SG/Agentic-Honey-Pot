import requests

GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_result(session_id, is_scam, scam_type, tactics,
                      intelligence, total_messages, engagement_duration):
    
    allowed_keys = [
      "phoneNumbers",
      "bankAccounts",
      "upiIds",
      "phishingLinks",
      "emailAddresses"
    ]

    filtered_intelligence = {
      key: intelligence.get(key, [])
      for key in allowed_keys
    }
    payload = {
        "status": "completed",
        "sessionId": session_id,
        "scamDetected": is_scam,
        "scamType": scam_type,
        "extractedIntelligence": filtered_intelligence,
        "totalMessagesExchanged": total_messages,
        "engagementDurationSeconds": engagement_duration,
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": engagement_duration
        },
        "agentNotes": f"Tactics identified from scammer : {tactics}"
    }

    try:
        requests.post(GUVI_ENDPOINT, json=payload, timeout=5)
        print(payload)
        print("Status called")
    except Exception:
        pass
