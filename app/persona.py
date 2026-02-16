from app.client import call_mistral

def generate_persona_reply(message: str, history_text: str = ""):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a confused but cooperative person. "
                "Keep the scammer talking and ask for details like payment methods."
            )
        },
        {
            "role": "user",
            "content": f"""
Conversation history:
{history_text}

Scammer said:
{message}

Respond in 1 short sentence and ask a question.
"""
        }
    ]
    return call_mistral(messages)


def explain_scam(message: str) -> str:
    messages = [
        {
            "role": "system",
            "content": "You are a fraud detection assistant."
        },
        {
            "role": "user",
            "content": f"""
Classify the message.

Start response with:
'Spam - <Type> : Intent: <tactics>'
or
'Not Spam : Intent: <tactics>'

Message:
{message}
"""
        }
    ]
    return call_mistral(messages)
