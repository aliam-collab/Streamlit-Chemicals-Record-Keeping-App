import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
from io import StringIO
import bcrypt
import yagmail
from email_validator import validate_email, EmailNotValidError

DB_PATH = "chemicals.db"

# -------------------------
# Database helpers
# -------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # chemicals master list (private)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS chemicals (
        serial_no INTEGER,
        chemical TEXT PRIMARY KEY,
        amount_total REAL,
        amount_remaining REAL,
        issued_total REAL,
        unit TEXT,
        cas_no TEXT
    )""")

    # users table with hashed password and email
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        full_name TEXT,
        email TEXT,
        password_hash BLOB,
        role TEXT
    )""")

    # forgot password token table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS password_reset (
        username TEXT PRIMARY KEY,
        token TEXT,
        created_at TEXT
    )""")

    # requests made by users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        chemical TEXT NOT NULL,
        amount REAL NOT NULL,
        unit TEXT,
        note TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        supervisor TEXT,
        lab_incharge TEXT,
        created_at TEXT,
        updated_at TEXT
    )""")

    # issued records (per user)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS issued (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        chemical TEXT NOT NULL,
        amount REAL NOT NULL,
        unit TEXT,
        issued_by TEXT,
        issued_at TEXT
    )""")

    # notifications for users / lab / supervisor
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL,
        seen INTEGER NOT NULL DEFAULT 0,
        created_at TEXT
    )""")

    conn.commit()
    conn.close()

# -------------------------
# Utility operations
# -------------------------
def safe_query_df(query, params=()):
    conn = get_conn()
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df

def push_notification(recipient, message):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO notifications(recipient,message,created_at) VALUES (?,?,?)",
        (recipient, message, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

def get_unseen_notifications(user):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, message, created_at FROM notifications WHERE recipient=? AND seen=0 ORDER BY created_at DESC", (user,))
    rows = cur.fetchall()
    conn.close()
    return rows

def mark_notifications_seen(ids):
    if not ids:
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.executemany("UPDATE notifications SET seen=1 WHERE id=?", [(i,) for i in ids])
    conn.commit()
    conn.close()

# -------------------------
# Authentication
# -------------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def signup_user(username, full_name, email, password, role):
    conn = get_conn()
    cur = conn.cursor()
    try:
        # check email validity
        validate_email(email)
        pw_hash = hash_password(password)
        cur.execute("INSERT INTO users(username,full_name,email,password_hash,role) VALUES (?,?,?,?,?)",
                    (username, full_name, email, pw_hash, role))
        conn.commit()
        return True, "Signup successful."
    except EmailNotValidError:
        return False, "Invalid email address."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        conn.close()

def login_user(username, password):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return False, "User not found."
    pw_hash, role = r
    if check_password(password, pw_hash):
        return True, role
    else:
        return False, "Incorrect password."

def send_reset_email(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return False, "User not found."
    email = r[0]
    import secrets
    token = secrets.token_urlsafe(16)
    now = datetime.utcnow().isoformat()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO password_reset(username,token,created_at) VALUES (?,?,?)",
                (username, token, now))
    conn.commit()
    conn.close()
    # Send email
    # Replace with your Gmail credentials
    GMAIL_USER = "YOUR_GMAIL@gmail.com"
    GMAIL_PASS = "YOUR_APP_PASSWORD"
    try:
        yag = yagmail.SMTP(GMAIL_USER, GMAIL_PASS)
        reset_link = f"https://yourdomain.com/reset?username={username}&token={token}"
        yag.send(email, "Password Reset Link", f"Click here to reset your password: {reset_link}")
        return True, "Reset link sent to email."
    except Exception as e:
        return False, str(e)

# -------------------------
# Chemical operations (similar to your previous code)
# -------------------------
def load_chemicals():
    return safe_query_df("SELECT serial_no,chemical,amount_total,amount_remaining,issued_total,unit,cas_no FROM chemicals ORDER BY serial_no")

def upload_master_from_excel(uploaded_file):
    df = pd.read_excel(uploaded_file)
    df.columns = df.columns.str.strip()
    required = ["S.NO.", "Names", "Quantity", "Units", "Q.Issued", "Q.Remaining", "CAS.No."]
    if not all(col in df.columns for col in required):
        raise ValueError("Excel must contain columns: " + ", ".join(required))
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM chemicals")
    for _, r in df.iterrows():
        serial = int(r["S.NO."]) if not pd.isna(r["S.NO."]) else None
        name = str(r["Names"]).strip()
        qty = float(r["Quantity"]) if not pd.isna(r["Quantity"]) else 0.0
        unit = str(r["Units"]).strip()
        issued_total = float(r["Q.Issued"]) if not pd.isna(r["Q.Issued"]) else 0.0
        remaining = float(r["Q.Remaining"]) if not pd.isna(r["Q.Remaining"]) else qty - issued_total
        cas = str(r["CAS.No."]).strip()
        cur.execute("""
            INSERT INTO chemicals(serial_no,chemical,amount_total,amount_remaining,issued_total,unit,cas_no)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(chemical) DO UPDATE SET
                serial_no=excluded.serial_no,
                amount_total=excluded.amount_total,
                amount_remaining=excluded.amount_remaining,
                issued_total=excluded.issued_total,
                unit=excluded.unit,
                cas_no=excluded.cas_no
        """, (serial, name, qty, remaining, issued_total, unit, cas))
    conn.commit()
    conn.close()
    return True

# -------------------------
# Streamlit UI
# -------------------------
def main():
    st.set_page_config(page_title="Chemical Record Keeper", layout="wide")
    init_db()

    st.title("Chemical Record Keeper App with Secure Login")

    menu = ["Login", "Signup", "Forgot Password"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Signup":
        st.subheader("Create a new account")
        username = st.text_input("Username")
        full_name = st.text_input("Full Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["User", "Supervisor", "Lab"])
        if st.button("Signup"):
            ok, msg = signup_user(username.strip(), full_name.strip(), email.strip(), password, role)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

    elif choice == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            ok, result = login_user(username.strip(), password)
            if ok:
                st.session_state['user'] = {"username": username.strip(), "role": result}
                st.success(f"Logged in as {username.strip()} ({result})")
            else:
                st.error(result)

    elif choice == "Forgot Password":
        st.subheader("Forgot Password")
        username = st.text_input("Enter your username")
        if st.button("Send Reset Link"):
            ok, msg = send_reset_email(username.strip())
            if ok:
                st.success(msg)
            else:
                st.error(msg)

    # After login, show dashboard
    if 'user' in st.session_state and st.session_state['user'] is not None:
        user = st.session_state['user']
        st.info(f"Logged in as {user['username']} ({user['role']})")

        st.subheader("Master Chemical List")
        chems = load_chemicals()
        st.dataframe(chems)

        st.subheader("Upload / Replace Master List (Lab Only)")
        if user['role'] == "Lab":
            uploaded = st.file_uploader("Upload .xlsx file", type=["xlsx"])
            if uploaded is not None:
                try:
                    upload_master_from_excel(uploaded)
                    st.success("Master list uploaded.")
                except Exception as e:
                    st.error(str(e))

if __name__ == "__main__":
    main()
