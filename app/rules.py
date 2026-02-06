import re


UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-]{2,}\b"
BANK_REGEX = r"\b(?:account|acc|a\/c|ac)(?:\s*(?:no|number|#))?\s*(?:is|:|-|\()?(\d{9,18})\)?\b"
GENERIC_ACCOUNT_REGEX = r"\b\d{12,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"
PHONE_REGEX = r"\+91[\-\s]?\d{10}|\b[6-9]\d{9}\b"
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
    bank_accounts = re.findall(BANK_REGEX, message, re.IGNORECASE)
    generic_accounts = re.findall(GENERIC_ACCOUNT_REGEX, message)

    # remove accounts that are actually phone numbers
    phones = re.findall(PHONE_REGEX, message)

    all_accounts = list(set(bank_accounts + generic_accounts))
    all_accounts = [acc for acc in all_accounts if acc not in phones]
    print("Came")
    return {
        "upi_ids": re.findall(UPI_REGEX, message),
        "bank_accounts": all_accounts,
        "ifsc_codes": re.findall(IFSC_REGEX, message),
        "phishing_links": re.findall(URL_REGEX, message),
        "phone_numbers": phones,
        "keywords": keywords_found
    }

