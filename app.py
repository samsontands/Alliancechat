import streamlit as st
import hashlib
import sqlite3
from datetime import datetime
import os

# Set page configuration
st.set_page_config(page_title="Streamlit Chat App", page_icon="💬", layout="wide")

# Initialize session state variables
if 'username' not in st.session_state:
    st.session_state.username = None
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'messages' not in st.session_state:
    st.session_state.messages = []

# Database setup
DB_FILE = "chat_app.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  message TEXT,
                  timestamp DATETIME)''')
    conn.commit()
    conn.close()

init_db()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def sign_up():
    st.subheader("Sign Up")
    new_user = st.text_input("Username", key="signup_username")
    new_password = st.text_input("Password", type="password", key="signup_password")
    if st.button("Sign Up"):
        conn = get_db_connection()
        c = conn.cursor()
        hashed_password = hash_password(new_password)
        try:
            c.execute("INSERT INTO users VALUES (?, ?)", (new_user, hashed_password))
            conn.commit()
            st.success("You have successfully signed up!")
        except sqlite3.IntegrityError:
            st.error("Username already exists. Please choose a different one.")
        finally:
            conn.close()

def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        conn = get_db_connection()
        c = conn.cursor()
        hashed_password = hash_password(password)
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
        result = c.fetchone()
        conn.close()
        if result:
            st.session_state.username = username
            st.success("Logged in successfully!")
        else:
            st.error("Incorrect username or password")

def logout():
    st.session_state.username = None
    st.success("Logged out successfully!")

def get_messages():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 100")
    messages = c.fetchall()
    conn.close()
    return messages

def send_message(username, message):
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
              (username, message, timestamp))
    conn.commit()
    conn.close()

def main():
    st.title("Streamlit Chat App")

    if st.session_state.username is None:
        col1, col2 = st.columns(2)
        with col1:
            sign_up()
        with col2:
            login()
    else:
        st.write(f"Welcome, {st.session_state.username}!")
        if st.button("Logout"):
            logout()

        st.subheader("Chat")
        message = st.text_input("Type your message")
        if st.button("Send"):
            if message:
                send_message(st.session_state.username, message)
                st.success("Message sent!")

        st.subheader("Chat History")
        messages = get_messages()
        for msg in messages:
            st.text(f"{msg['username']} ({msg['timestamp']}): {msg['message']}")

if __name__ == "__main__":
    main()
