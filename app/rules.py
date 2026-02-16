import re

UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-]{2,}\b"
BANK_REGEX = r"\b\d{12,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"
PHONE_REGEX = r"\b(?:\+91[\s-]?|0)?[6-9]\d{9}\b"
EMAIL_REGEX = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

SCAM_KEYWORDS = [
    "urgent", "blocked", "suspended", "verify", "kyc",
    "transfer", "send money", "otp", "account", "penalty",
    "immediately", "limited time"
]


def analyze_message(message: str):
    if not message:
        return empty_result()

    text = message.lower()

    keywords_found = [k for k in SCAM_KEYWORDS if k in text]

    upi_ids = re.findall(UPI_REGEX, message)
    bank_accounts = re.findall(BANK_REGEX, message)
    ifsc_codes = re.findall(IFSC_REGEX, message)
    links = re.findall(URL_REGEX, message)
    phones = re.findall(PHONE_REGEX, message)
    emails = re.findall(EMAIL_REGEX, message)

    return {
        "upi_ids": list(set(upi_ids)),
        "bank_accounts": list(set(bank_accounts)),
        "ifsc_codes": list(set(ifsc_codes)),
        "phishing_links": [l[0] if isinstance(l, tuple) else l for l in links],
        "phone_numbers": list(set(phones)),
        "emailAddresses": list(set(emails)),
        "keywords": keywords_found
    }


def empty_result():
    return {
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "phishing_links": [],
        "phone_numbers": [],
        "emailAddresses": [],
        "keywords": []
    }
