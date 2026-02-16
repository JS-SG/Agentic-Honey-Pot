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
