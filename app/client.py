import os
import requests
from dotenv import load_dotenv

load_dotenv()

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
API_KEY = os.getenv("MISTRAL_API_KEY")

def call_mistral(messages):
    try:
        response = requests.post(
            MISTRAL_API_URL,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "mistral-small-latest",
                "messages": messages,
                "temperature": 0.4
            },
            timeout=10
        )
        data = response.json()
        return data["choices"][0]["message"]["content"]

    except Exception as e:
        print("Mistral error:", str(e))
        return "Can you explain that again?"


