import sqlite3

DB = "honeypot1.db"


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS intelligence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        upi TEXT,
        bank TEXT,
        ifsc TEXT,
        link TEXT,
        phone TEXT,
        email TEXT,
        keyword TEXT
    )
    """)
    conn.commit()
    conn.close()

def get_session_intelligence(session_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
        SELECT upi, bank, ifsc, link, phone, email, keyword
        FROM intelligence
        WHERE session_id = ?
    """, (session_id,))

    rows = cur.fetchall()
    conn.close()

    result = {
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "phishing_links": [],
        "phone_numbers": [],
        "emailAddresses": [],
        "keywords": []
    }

    for row in rows:
        upi, bank, ifsc, link, phone, email, keyword = row

        if upi:
            result["upi_ids"].append(upi)
        if bank:
            result["bank_accounts"].append(bank)
        if ifsc:
            result["ifsc_codes"].append(ifsc)
        if link:
            result["phishing_links"].append(link)
        if phone:
            result["phone_numbers"].append(phone)
        if email:
            result["emailAddresses"].append(email)
        if keyword:
            result["keywords"].append(keyword)

    # Remove duplicates
    for key in result:
        result[key] = list(set(result[key]))

    return result


def save_intelligence(session_id, **kwargs):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute(
        """INSERT INTO intelligence
        (session_id, upi, bank, ifsc, link, phone, email, keyword)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            session_id,
            kwargs.get("upi"),
            kwargs.get("bank"),
            kwargs.get("ifsc"),
            kwargs.get("link"),
            kwargs.get("phone"),
            kwargs.get("email"),
            kwargs.get("keyword")
        )
    )

    conn.commit()
    conn.close()

