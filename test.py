import os
import requests

key = os.getenv("MISTRAL_API_KEY")
print(key)
response = requests.post(
    "https://api.mistral.ai/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    },
    json={
        "model": "mistral-small-latest",
        "messages": [
            {"role": "user", "content": "Explain why OTP scams are dangerous"}
        ]
    }
)

print(response.json()["choices"][0]["message"]["content"])
