from dotenv import load_dotenv
import requests
import os
import base64

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # Set your API key in environment


def encode_url_for_virustotal(url: str) -> str:
    url_bytes = url.encode('utf-8')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    return base64_bytes.decode('utf-8').rstrip("=")


def check_url_virustotal(url: str):
    encoded_url = encode_url_for_virustotal(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(api_url, headers=headers, timeout=10)
    if response.status_code == 200:
        data = response.json()
        # Get the malicious / suspicious score
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
    else:
        return {
            "url": url,
            "error": f"HTTP {response.status_code}"
        }
