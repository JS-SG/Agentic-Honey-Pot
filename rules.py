import re


UPI_REGEX = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"
BANK_REGEX = r"(?:account|acc|a\/c|ac)\s*(?:no|number|#)?[:\s-]*(\d{9,18})"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
URL_REGEX = r"https?://[^\s]+"
PHONE_REGEX = r"\+?\d{10,13}"
KEYWORDS = ["urgent", "verify", "blocked", "suspended", "account", "transfer",  "inactive", "immediately",
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
    "verify", "kyc", "otp"]

def analyze_message(message: str):
    lower = message.lower()
    keywords_found = [k for k in KEYWORDS if k in lower]
    print("Came")
    return {
        "upi_ids": re.findall(UPI_REGEX, message),
        "bank_accounts": re.findall(BANK_REGEX, message, re.IGNORECASE),
        "ifsc_codes": re.findall(IFSC_REGEX, message),
        "phishing_links": re.findall(URL_REGEX, message),
        "phone_numbers": re.findall(PHONE_REGEX, message),
        "keywords": keywords_found
    }

