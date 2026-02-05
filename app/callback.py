import requests

GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_result(session_id, is_scam, scam_type, tactics, intelligence, total_messages):
    payload = {
        "sessionId": session_id,
        "scamDetected": is_scam,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": intelligence.get("bank_accounts", []),
            "upiIds": intelligence.get("upi_ids", []),
            "phishingLinks": intelligence.get("phishing_links", []),
            "phoneNumbers": intelligence.get("phone_numbers", []),
            "suspiciousKeywords": intelligence.get("keywords", [])
        },
        "agentNotes": f"Scammer used {scam_type} type scam and tactics like {tactics}"
    }

    try:
        response = requests.post(
            GUVI_ENDPOINT,
            json=payload,
            timeout=5
        )
        print("GUVI callback status:", response.status_code)
    except Exception as e:
        print("Callback failed:", str(e))
