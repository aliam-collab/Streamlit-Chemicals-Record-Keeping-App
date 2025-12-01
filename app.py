import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
from io import StringIO
import hashlib
import smtplib
from email.message import EmailMessage
import random
import string

DB_PATH = "chemicals.db"

# -------------------------
# Database helpers
# -------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Chemicals
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

    # Users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        full_name TEXT,
        email TEXT,
        password_hash TEXT,
        role TEXT
    )""")

    # Password reset tokens
    cur.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        username TEXT,
        token TEXT,
        created_at TEXT
    )""")

    # Requests
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

    # Issued
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

    # Notifications
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
# Utilities
# -------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def safe_query_df(query, params=()):
    conn = get_conn()
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df

def push_notification(recipient, message):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO notifications(recipient,message,created_at) VALUES (?,?,?)",
                (recipient, message, datetime.utcnow().isoformat()))
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
# Users
# -------------------------
def signup(username, password, email, role):
    conn = get_conn()
    cur = conn.cursor()
    pw_hash = hash_password(password)
    try:
        cur.execute("INSERT INTO users(username,email,password_hash,role,full_name) VALUES (?,?,?,?,?)",
                    (username, email, pw_hash, role, username))
        conn.commit()
        return True, "Signup successful"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    finally:
        conn.close()

def login_user(username, password):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    conn.close()
    if r and hash_password(password) == r[0]:
        return True, r[1]
    return False, None

# -------------------------
# Forgot password
# -------------------------
def send_reset_email(username, token):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    if not r:
        conn.close()
        return False, "User not found"
    email_address = r[0]
    conn.close()

    # SMTP email setup (use your Gmail app password)
    SMTP_EMAIL = "your_gmail@gmail.com"
    SMTP_PASS = "your_app_password"

    try:
        msg = EmailMessage()
        msg.set_content(f"Password reset token: {token}\nUse this in the app to reset your password.")
        msg['Subject'] = "Chemical Record Keeper Password Reset"
        msg['From'] = SMTP_EMAIL
        msg['To'] = email_address

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_PASS)
            smtp.send_message(msg)
        return True, "Reset email sent"
    except Exception as e:
        return False, str(e)

def generate_reset_token(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_password_reset(username):
    token = generate_reset_token()
    now = datetime.utcnow().isoformat()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO password_resets(username,token,created_at) VALUES (?,?,?)", (username, token, now))
    conn.commit()
    conn.close()
    return token

def reset_password(username, token, new_password):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT token, created_at FROM password_resets WHERE username=? ORDER BY created_at DESC LIMIT 1", (username,))
    r = cur.fetchone()
    if not r or r[0] != token:
        conn.close()
        return False, "Invalid token"
    # reset password
    pw_hash = hash_password(new_password)
    cur.execute("UPDATE users SET password_hash=? WHERE username=?", (pw_hash, username))
    conn.commit()
    conn.close()
    return True, "Password reset successfully"

# -------------------------
# Chemical master list
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
        unit = str(r["Units"]).strip() if "Units" in r and not pd.isna(r["Units"]) else ""
        issued_total = float(r["Q.Issued"]) if not pd.isna(r["Q.Issued"]) else 0.0
        remaining = float(r["Q.Remaining"]) if not pd.isna(r["Q.Remaining"]) else qty - issued_total
        cas = str(r["CAS.No."]).strip() if not pd.isna(r["CAS.No."]) else ""
        cur.execute("""
            INSERT INTO chemicals(serial_no,chemical,amount_total,amount_remaining,issued_total,unit,cas_no)
            VALUES (?,?,?,?,?,?,?)
        """, (serial, name, qty, remaining, issued_total, unit, cas))
    conn.commit()
    conn.close()
    return True

# -------------------------
# Requests & issuance
# -------------------------
def create_request(username, chemical, amount, unit, note=""):
    now = datetime.utcnow().isoformat()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT amount_remaining, unit FROM chemicals WHERE chemical=?", (chemical,))
    r = cur.fetchone()
    if r:
        remaining, chem_unit = r
        if unit != chem_unit:
            conn.close()
            return False, f"Unit mismatch! Master list uses {chem_unit}."
        if float(amount) > float(remaining):
            conn.close()
            return False, f"Requested amount ({amount}) exceeds remaining stock ({remaining})."
    cur.execute("INSERT INTO requests(username,chemical,amount,unit,note,status,created_at,updated_at) VALUES (?,?,?,?,?,'Pending',?,?)",
                (username, chemical, amount, unit, note, now, now))
    conn.commit()
    conn.close()
    return True, "Request created"

def list_requests(filters=None):
    base = "SELECT id,username,chemical,amount,unit,note,status,supervisor,lab_incharge,created_at,updated_at FROM requests"
    params = []
    if filters:
        clauses=[]
        for k,v in filters.items():
            clauses.append(f"{k}=?")
            params.append(v)
        base += " WHERE " + " AND ".join(clauses)
    base += " ORDER BY created_at DESC"
    return safe_query_df(base, params)

def update_request_status(rid, status, supervisor=None, lab_incharge=None):
    now = datetime.utcnow().isoformat()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT status, username, chemical, amount, unit FROM requests WHERE id=?", (rid,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False, "Request not found"
    old_status, req_user, chem, amt, unit = row
    if status=="Approved":
        cur.execute("UPDATE requests SET status=?, supervisor=?, updated_at=? WHERE id=?", (status, supervisor, now, rid))
        conn.commit()
        conn.close()
        push_notification(req_user, f"Your request #{rid} for {amt} {unit} {chem} was APPROVED by {supervisor}.")
        push_notification("lab_incharge", f"Request #{rid} for {amt} {unit} {chem} by {req_user} approved by {supervisor}.")
        return True,"Approved"
    elif status=="Rejected":
        cur.execute("UPDATE requests SET status=?, supervisor=?, updated_at=? WHERE id=?", (status, supervisor, now, rid))
        conn.commit()
        conn.close()
        push_notification(req_user, f"Your request #{rid} for {amt} {unit} {chem} was REJECTED by {supervisor}.")
        return True,"Rejected"
    elif status=="Issued":
        cur.execute("SELECT amount_remaining FROM chemicals WHERE chemical=?", (chem,))
        remaining = cur.fetchone()[0]
        if amt>remaining:
            conn.close()
            return False,f"Insufficient stock. Remaining: {remaining}"
        cur.execute("UPDATE chemicals SET amount_remaining=amount_remaining-?, issued_total=issued_total+? WHERE chemical=?",(amt, amt, chem))
        cur.execute("UPDATE requests SET status=?, lab_incharge=?, updated_at=? WHERE id=?",(status, lab_incharge, now, rid))
        cur.execute("INSERT INTO issued(username,chemical,amount,unit,issued_by,issued_at) VALUES (?,?,?,?,?,?)",(req_user, chem, amt, unit, lab_incharge, now))
        conn.commit()
        conn.close()
        push_notification(req_user, f"Your request #{rid} for {amt} {unit} {chem} has been ISSUED by {lab_incharge}.")
        return True,"Issued"
    else:
        conn.close()
        return False,"Unsupported status"

def list_issued(filters=None):
    base = "SELECT id,username,chemical,amount,unit,issued_by,issued_at FROM issued"
    params=[]
    if filters:
        clauses=[]
        for k,v in filters.items():
            clauses.append(f"{k}=?")
            params.append(v)
        base += " WHERE " + " AND ".join(clauses)
    base += " ORDER BY issued_at DESC"
    return safe_query_df(base, params)

# -------------------------
# Streamlit UI
# -------------------------
def main():
    st.set_page_config(page_title="Chemical Record Keeper", layout="wide")
    init_db()

    if 'user' not in st.session_state:
        st.session_state['user'] = None

    st.sidebar.title("Account")
    mode = st.sidebar.radio("Mode", ["Login","Signup","Forgot Password"])
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    email = st.sidebar.text_input("Email (for signup/reset)")

    if st.sidebar.button("Submit"):
        if mode=="Signup":
            role = st.sidebar.selectbox("Role", ["User","Supervisor","Lab"])
            ok,msg = signup(username.strip(), password.strip(), email.strip(), role)
            if ok: st.success(msg)
            else: st.error(msg)
        elif mode=="Login":
            ok, role = login_user(username.strip(), password.strip())
            if ok:
                st.session_state['user']={"username":username.strip(),"role":role}
                st.success(f"Logged in as {username} ({role})")
            else:
                st.error("Invalid credentials")
        elif mode=="Forgot Password":
            token = create_password_reset(username.strip())
            ok,msg = send_reset_email(username.strip(), token)
            if ok: st.success(msg)
            else: st.error(msg)

    if 'user' not in st.session_state or st.session_state['user'] is None:
        st.info("Please login/signup to continue")
        return

    user = st.session_state['user']
    st.write(f"Logged in as {user['username']} ({user['role']})")
    # You can now add dashboards for User, Supervisor, Lab with chemical requests etc.

if __name__=="__main__":
    main()
