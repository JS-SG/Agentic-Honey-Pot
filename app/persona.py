# app/persona.py
from app.client import generate_persona_reply
from app.database import get_conversation

def generate_reply_ai(message: str, session_id: str) -> str:
    """
    Generates a believable AI persona reply to engage a scammer.
    """
    # Prepare conversation history for context
    history = get_conversation(session_id)
    response = generate_persona_reply(message, history)
    print(response)
    return response
