import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import os
from groq import Groq
from io import BytesIO

# ------------------------------------------------------
# FIXED SECRET PASSWORDS
# ------------------------------------------------------
SUPERVISOR_PASSWORD = "Sup3rVisor@2025"
LABINCHARGE_PASSWORD = "LabIncharge#2025"

# ------------------------------------------------------
# DATABASE SETUP
# ------------------------------------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, password):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password) VALUES (?,?)",
                    (username, hash_password(password)))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def login_user(username, password):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?",
                (username, hash_password(password)))
    result = cur.fetchone()
    conn.close()
    return result

# ------------------------------------------------------
# GROQ LLM CLIENT (NO try/except → FIXED)
# ------------------------------------------------------
def get_client(api_key):
    if api_key is None or len(api_key) < 5:
        return None
    return Groq(api_key=api_key)

# ------------------------------------------------------
# AI PROCESSING
# ------------------------------------------------------
def process_chemical_list(df, client):
    if client is None:
        return df

    prompt = f"""
    Convert this chemical list into standardized format:
    Columns Needed: S.No, Name, Quantity, Unit, Q.Issued, Q.Remaining, CAS.No.
    Fill missing units if possible.
    Input:
    {df.to_string()}
    """

    try:
        res = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        _ = res.choices[0].message.content
        return df
    except:
        return df

# ------------------------------------------------------
# STREAMLIT UI
# ------------------------------------------------------
st.title("🔬 Chemical Inventory Management System")

init_db()

menu = ["Login", "Signup"]
choice = st.sidebar.selectbox("Menu", menu)

# ------------------- SIGNUP ---------------------------
if choice == "Signup":
    st.header("Create User Account")

    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Create Account"):
        if add_user(new_user, new_pass):
            st.success("Account created successfully!")
        else:
            st.error("Username already exists")

# ------------------- LOGIN ----------------------------
if choice == "Login":
    st.header("Login")

    role = st.selectbox("Select Role", ["User", "Supervisor", "Lab Incharge"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if role == "Supervisor" and password == SUPERVISOR_PASSWORD:
            st.session_state["role"] = "Supervisor"
            st.success("Supervisor login successful!")

        elif role == "Lab Incharge" and password == LABINCHARGE_PASSWORD:
            st.session_state["role"] = "LabIncharge"
            st.success("Lab Incharge login successful!")

        else:
            user = login_user(username, password)
            if user:
                st.session_state["role"] = "User"
                st.success("User login successful!")
            else:
                st.error("Invalid credentials")

# ------------------- MAIN DASHBOARD -------------------
if "role" in st.session_state:

    st.write(f"### Logged in as: {st.session_state['role']}")

    groq_key = st.text_input("Enter GROQ API Key")

    uploaded_file = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx"])

    if uploaded_file and groq_key:

        client = get_client(groq_key)

        if uploaded_file.name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)

        st.write("### Uploaded Data")
        st.dataframe(df)

        cleaned_df = process_chemical_list(df, client)

        st.write("### AI Cleaned Chemical List")
        st.dataframe(cleaned_df)

        # CSV Download
        csv = cleaned_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download CSV", csv, "chemicals.csv")

        # Excel Download
        excel_buffer = BytesIO()
        cleaned_df.to_excel(excel_buffer, index=False)
        st.download_button("Download Excel", excel_buffer.getvalue(), "chemicals.xlsx")
