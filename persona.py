from app2.client import call_mistral

def generate_persona_reply(message: str, history_text: str = ""):
    messages = [
        {
            "role": "system",
            "content": "You are a believable AI persona interacting with a potential scammer."
        },
        {
            "role": "user",
            "content": f"""
Engage the scammer naturally, keep them talking, and try to get details like UPI ID, bank accounts, phone numbers, or phishing links.
Conversation history:
{history_text}

Scammer said:
{message}

Respond in 1 to 2 sentences.
"""
        }
    ]
    return call_mistral(messages)
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
Respond by start the response with either:
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
'Intent: ' Which spam tactics the scammers use in 5 to 6 words
Message:
{message}
"""
        }
    ]
    return call_mistral(messages)
