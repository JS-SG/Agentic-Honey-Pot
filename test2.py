from client import generate_persona_reply

scammer_message = "Please send your bank account details to get the prize."
history = "You are talking to a scammer who claims to have won a prize."

reply = generate_persona_reply(scammer_message, conversation_history=history)
print("AI Persona Reply:")
print(reply)
