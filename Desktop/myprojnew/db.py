


import sqlite3
import hashlib
import re
import pandas as pd

# ---------------- HASH FUNCTION ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------- VALIDATION FUNCTIONS ----------------
def validate_username(username):
    return username.startswith("CW")


def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


# ---------------- INIT DB ----------------
def init_db():
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    # ✅ logs table (with username)
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            input TEXT,
            tool TEXT,
            output TEXT
        )
    """)

    # ✅ users table (with role)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    conn.commit()
    conn.close()


# ---------------- CREATE USER ----------------
def create_user(username, password):

    if not validate_username(username):
        return "INVALID_USERNAME"

    if not validate_password(password):
        return "WEAK_PASSWORD"

    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    hashed_pw = hash_password(password)

    try:
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_pw, "user")  # default role
        )
        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()
        return "USER_EXISTS"

    conn.close()
    return "SUCCESS"


# ---------------- CREATE ADMIN (RUN ONCE) ----------------
def create_admin():
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    admin_username = "CW_admin"
    admin_password = hash_password("Admin@123")

    try:
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (admin_username, admin_password, "admin")
        )
        conn.commit()
    except:
        pass  # already exists

    conn.close()


# ---------------- AUTHENTICATE ----------------
def authenticate_user(username, password):
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    hashed_pw = hash_password(password)

    c.execute(
        "SELECT username, role FROM users WHERE username=? AND password=?",
        (username, hashed_pw)
    )

    user = c.fetchone()
    conn.close()

    return user  # (username, role) or None


# ---------------- UPDATE PASSWORD ----------------
def update_password(username, new_password):

    if not validate_password(new_password):
        return "WEAK_PASSWORD"

    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    hashed_pw = hash_password(new_password)

    c.execute(
        "UPDATE users SET password=? WHERE username=?",
        (hashed_pw, username)
    )

    conn.commit()
    conn.close()

    return "SUCCESS"


# ---------------- SAVE LOG ----------------
def save_log(username, inp, tool, output):
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO logs (username, input, tool, output) VALUES (?, ?, ?, ?)",
        (username, inp, tool, output)
    )

    conn.commit()
    conn.close()


# ---------------- LOAD LOGS ----------------
def load_logs(username, role):
    conn = sqlite3.connect("logs.db")

    if role == "admin":
        query = "SELECT * FROM logs"
        df = pd.read_sql_query(query, conn)
    else:
        query = "SELECT * FROM logs WHERE username=?"
        df = pd.read_sql_query(query, conn, params=(username,))

    conn.close()
    return df