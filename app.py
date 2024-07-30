import streamlit as st
import hashlib
import sqlite3
from datetime import datetime

# Initialize session state variables
if 'username' not in st.session_state:
    st.session_state.username = None
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'messages' not in st.session_state:
    st.session_state.messages = []

# Database setup
conn = sqlite3.connect('chat_app.db')
c = conn.cursor()

# Create users table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password TEXT)''')

# Create messages table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS messages
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT,
              message TEXT,
              timestamp DATETIME)''')

conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def sign_up():
    st.subheader("Sign Up")
    new_user = st.text_input("Username")
    new_password = st.text_input("Password", type="password")
    if st.button("Sign Up"):
        hashed_password = hash_password(new_password)
        try:
            c.execute("INSERT INTO users VALUES (?, ?)", (new_user, hashed_password))
            conn.commit()
            st.success("You have successfully signed up!")
        except sqlite3.IntegrityError:
            st.error("Username already exists. Please choose a different one.")

def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        hashed_password = hash_password(password)
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
        result = c.fetchone()
        if result:
            st.session_state.username = username
            st.success("Logged in successfully!")
        else:
            st.error("Incorrect username or password")

def logout():
    st.session_state.username = None
    st.success("Logged out successfully!")

def get_messages():
    c.execute("SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 100")
    return c.fetchall()

def send_message(username, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
              (username, message, timestamp))
    conn.commit()

def main():
    st.title("Streamlit Chat App")

    if st.session_state.username is None:
        sign_up()
        st.markdown("---")
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
            st.text(f"{msg[0]} ({msg[2]}): {msg[1]}")

if __name__ == "__main__":
    main()
