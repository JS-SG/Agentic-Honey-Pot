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
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        is_scam BOOLEAN,
        scam_type TEXT,
        tactics TEXT,
        engagement_duration INTEGER,
        message_count INTEGER
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

def update_session_status(session_id, is_scam, scam_type, tactics, duration, count):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO sessions (session_id, is_scam, scam_type, tactics, engagement_duration, message_count)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, is_scam, scam_type, tactics, duration, count))
    conn.commit()
    conn.close()

def get_session_status(session_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT is_scam, scam_type, tactics, engagement_duration, message_count FROM sessions WHERE session_id=?", (session_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "is_scam": bool(row[0]),
            "scam_type": row[1],
            "tactics": row[2],
            "engagement_duration": row[3],
            "message_count": row[4]
        }
    return None



