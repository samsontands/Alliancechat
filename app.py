import streamlit as st
from datetime import datetime

# Set page configuration
st.set_page_config(page_title="Streamlit Chat App", page_icon="💬", layout="wide")

# Initialize session state variables
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

def sign_up():
    st.subheader("Sign Up")
    new_user = st.text_input("Username", key="signup_username")
    new_password = st.text_input("Password", type="password", key="signup_password")
    if st.button("Sign Up"):
        if new_user and new_password:
            if new_user not in st.session_state.users:
                st.session_state.users[new_user] = new_password
                st.success("You have successfully signed up!")
            else:
                st.error("Username already exists. Please choose a different one.")
        else:
            st.error("Please enter both username and password.")

def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        if username in st.session_state.users and st.session_state.users[username] == password:
            st.session_state.current_user = username
            st.success("Logged in successfully!")
        else:
            st.error("Incorrect username or password")

def logout():
    st.session_state.current_user = None
    st.success("Logged out successfully!")

def send_message(username, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.messages.append((username, message, timestamp))

def main():
    st.title("Streamlit Chat App")

    if st.session_state.current_user is None:
        col1, col2 = st.columns(2)
        with col1:
            sign_up()
        with col2:
            login()
    else:
        st.write(f"Welcome, {st.session_state.current_user}!")
        if st.button("Logout"):
            logout()

        st.subheader("Chat")
        message = st.text_input("Type your message")
        if st.button("Send"):
            if message:
                send_message(st.session_state.current_user, message)
                st.success("Message sent!")

        st.subheader("Chat History")
        for username, msg, timestamp in reversed(st.session_state.messages):
            st.text(f"{username} ({timestamp}): {msg}")

if __name__ == "__main__":
    main()
