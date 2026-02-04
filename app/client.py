# client.py
from dotenv import load_dotenv
import os
import requests

load_dotenv()

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
MISTRAL_MODEL = "mistral-small-latest"


def call_mistral(messages, temperature=0.2, timeout=10):
    """
    Generic Mistral API call.
    """
    try:
        response = requests.post(
            MISTRAL_API_URL,
            headers={
                "Authorization": f"Bearer {os.getenv('MISTRAL_API_KEY')}",
                "Content-Type": "application/json"
            },
            json={
                "model": MISTRAL_MODEL,
                "messages": messages,
                "temperature": temperature
            },
            timeout=timeout
        )
        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get(
            "content", "Explanation unavailable."
        )
    except Exception:
        return "Explanation unavailable due to system error."


def explain_scam(message: str) -> str:
    """
    Detect if a message is a scam.
    Returns a short explanation starting with 'Spam - <type> :' or 'Not Spam:'
    """
    messages = [
        {
            "role": "system",
            "content": "You are a fraud detection assistant."
        },
        {
            "role": "user",
            "content": f"""
Your task is to decide if a message is a scam or not.
Respond in 2 to 3 short sentences only.
Start the response with either:
'Spam - <Scam Type> :' if it is a scam
'Not Spam:' if it is legitimate
Scam types can be:
- Financial Scam
- Phishing
- Loan Scam
- Job Scam
- Prize Scam
- OTP Scam
- Investment Scam
- Other
Then give a short reason.

Message:
{message}
"""
        }
    ]
    return call_mistral(messages)


def generate_persona_reply(message: str, conversation_history: str = "") -> str:
    """
    Generate AI persona reply to actively engage a scammer.
    Include conversation history to make multi-turn replies coherent.
    """
    prompt_messages = [
        {
            "role": "system",
            "content": "You are a believable AI persona interacting with a potential scammer."
        },
        {
            "role": "user",
            "content": f"""
Engage the scammer naturally, keep them talking, and try to get details like UPI ID, bank accounts, or phishing links.
Conversation history:
{conversation_history}
Scammer said: {message}
Respond naturally in 2 to 3 sentences.
"""
        }
    ]
    return call_mistral(prompt_messages)
