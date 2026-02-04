# app/database.py
import sqlite3
import os

DB_PATH = "honeypot.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            messages TEXT
        )
    """)
    conn.commit()
    conn.close()

import sqlite3

DB_PATH = "honeypot.db"  # replace with your DB path

def save_message(session_id: str, sender: str, message: str, scam_detected: int ):
    """
    Save the last message in the sessions table.
    If the session exists, update last_message and scam_detected.
    If not, create a new session.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Combine sender and message for storage
    last_message = f"{sender}: {message}"

    # Check if session exists
    cur.execute("SELECT session_id FROM sessions WHERE session_id=?", (session_id,))
    row = cur.fetchone()

    if row:
        cur.execute(
            "UPDATE sessions SET last_message=?, scam_detected=? WHERE session_id=?",
            (last_message, scam_detected, session_id)
        )
    else:
        cur.execute(
            "INSERT INTO sessions(session_id, last_message, scam_detected) VALUES (?, ?, ?)",
            (session_id, last_message, scam_detected)
        )

    conn.commit()
    conn.close()

def get_session_intelligence(session_id: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT upi_id, bank_account, ifsc_code, phishing_link
        FROM intelligence
        WHERE session_id=?
    """, (session_id,))

    rows = cur.fetchall()
    conn.close()

    upi_ids, accounts, ifscs, links = set(), set(), set(), set()

    for u, a, i, l in rows:
        if u: upi_ids.add(u)
        if a: accounts.add(a)
        if i: ifscs.add(i)
        if l: links.add(l)

    return {
        "upi_ids": list(upi_ids),
        "bank_accounts": list(accounts),
        "ifsc_codes": list(ifscs),
        "phishing_links": list(links)
    }


def get_conversation(session_id: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT last_message FROM sessions WHERE session_id=?", (session_id,))
    row = cur.fetchone()
    conn.close()
    if row and row[0]:
        return row[0]
    return ""

def save_intelligence(session_id, upi_id=None, bank_account=None, ifsc_code=None, phishing_link=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO intelligence (session_id, upi_id, bank_account, ifsc_code, phishing_link)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, upi_id, bank_account, ifsc_code, phishing_link))

    conn.commit()
    conn.close()

