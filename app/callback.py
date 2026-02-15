import requests

GUVI_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_result(session_id, is_scam, scam_type, tactics, intelligence, total_messages, engagement_duration):
    payload = {
        "status": "success",
        "scamDetected": is_scam,
        "scamType": scam_type,
        "extractedIntelligence": {
            "phoneNumbers": intelligence.get("phone_numbers", []),
            "bankAccounts": intelligence.get("bank_accounts", []),
            "upiIds": intelligence.get("upi_ids", []),
            "phishingLinks": intelligence.get("phishing_links", []),
            "emailAddresses": intelligence.get("emailAddresses",[])
        },
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": engagement_duration
        },
        "agentNotes": f"Scammer used {scam_type} type scam and tactics like {tactics}"
    }

    try:
        print(payload)
        response = requests.post(
            GUVI_ENDPOINT,
            json=payload,
            timeout=5
        )
        print("GUVI callback status:", response.status_code)
    except Exception as e:
        print("Callback failed:", str(e))
