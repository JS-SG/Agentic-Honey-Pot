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
        phone TEXT
    )
    """)
    conn.commit()
    conn.close()

def save_intelligence(session_id, upi=None, bank=None, ifsc=None, link=None, phone=None):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO intelligence(session_id, upi, bank, ifsc, link, phone) VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, upi, bank, ifsc, link, phone)
    )
    conn.commit()
    conn.close()


