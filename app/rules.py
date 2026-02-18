import re
UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-]{2,}\b"
BANK_REGEX = r"\b(?:account|acc|a\/c|ac)(?:\s*(?:no|number|#))?\s*(?:is|:|-|\()?(\d{9,18})\)?\b"
GENERIC_ACCOUNT_REGEX = r"\b\d{12,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9.-]+\.(com|in|net|org|co|info)(/[^\s]*)?)"
PHONE_REGEX = r"\b(?:\+91[\s-]?|0)?[6-9]\d{9}\b|\b1[0-9]{3}[-\s]?[0-9]{3}[-\s]?[0-9]{4}\b"
email_regex = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"


KEYWORDS = ["urgent", "verify", "blocked", "suspended", "account", "transfer",  "inactive", "immediately",
    "verify", "limited time",

    "bank", "account", "blocked", "digitally arrested", "suspended"

    "payment", "pay", "amount", "rs.", "₹",

    "insurance", "policy", "lic",

    "urgent", "immediately", "soon", "inactive", "pay now", "send money"

    "verify", "kyc", "otp"]

def analyze_message(message: str):
    lower = message.lower()
    keywords_found = [k for k in KEYWORDS if k in lower]
    bank_accounts = re.findall(BANK_REGEX, message, re.IGNORECASE)
    generic_accounts = re.findall(GENERIC_ACCOUNT_REGEX, message)
    phones = re.findall(PHONE_REGEX, message)
    emails = re.findall(email_regex, message)
    text_without_emails = message
    for email in emails:
        text_without_emails = text_without_emails.replace(email, "")
    all_accounts = list(set(bank_accounts + generic_accounts))
    all_accounts = [acc for acc in all_accounts if acc not in phones]
    print(emails)
    return {
        "upi_ids": re.findall(UPI_REGEX, text_without_emails),
        "bank_accounts": all_accounts,
        "ifsc_codes": re.findall(IFSC_REGEX, message),
        "phishing_links": re.findall(URL_REGEX, text_without_emails),
        "phone_numbers": phones,
        "emailAddresses": emails,
        "keywords": keywords_found
    }

