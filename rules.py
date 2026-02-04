from app.url import check_url_virustotal
import re

SCAM_KEYWORDS = [
    "inactive", "immediately",
    "verify", "limited time",
        # Banking
    "bank", "account", "blocked", "digitally arrested", "suspended"

    # Payment
    "payment", "pay", "amount", "rs.", "₹",

    # Insurance / Govt impersonation
    "insurance", "policy", "lic",

    # Urgency
    "urgent", "immediately", "soon", "inactive", "pay now", "send money"

    # Verification
    "verify", "kyc", "otp"
]

UPI_REGEX = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"
URL_REGEX = r"https?://[^\s]+"
BANK_ACCOUNT_REGEX = r"(?:account|acc|a\/c|ac)\s*(?:no|number|#)?[:\s-]*(\d{9,18})"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"

def analyze_message(message: str):
    score = 0

    for word in SCAM_KEYWORDS:
        if word in message.lower():
            score += 1

    upi_ids = re.findall(UPI_REGEX, message)
    urls = re.findall(URL_REGEX, message)
    bank_accounts = re.findall(BANK_ACCOUNT_REGEX, message, re.IGNORECASE)
    ifsc_codes = re.findall(IFSC_REGEX, message)
    print(bank_accounts)

    if upi_ids:
        score += 2
    if urls:
        score += 2

    scam_detected = score >= 3
    checked_urls = []

    for url in urls:
        result = check_url_virustotal(url)
        if result.get("malicious", 0) > 0 or result.get("suspicious", 0) > 0:
            status = "malicious"
        else:
            status = "safe"
        checked_urls.append({
            "url": url,
            "status": status
        })

    return {
        "scam_detected": scam_detected,
        "score": score,
        "upi_ids": upi_ids,
        "phishing_links": checked_urls,
        "bank_accounts": bank_accounts,
        "ifsc_codes": ifsc_codes
    }
