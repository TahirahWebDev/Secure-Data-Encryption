import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# -------------------- Constants --------------------
DATA_FILE = "data.json"
FERNET_KEY_FILE = "fernet.key"
MAX_ATTEMPTS = 3
COOLDOWN_TIME = 30  # seconds
MASTER_PASSWORD = "admin123"

# -------------------- Key Handling --------------------
def load_or_create_key():
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(key)
    return key

@st.cache_resource
def get_cipher():
    key = load_or_create_key()
    return Fernet(key)

cipher = get_cipher()

# -------------------- Utility Functions --------------------
def hash_passkey(passkey, salt=b"static_salt"):
    return urlsafe_b64encode(pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)).decode()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# -------------------- Streamlit State Init --------------------
if "users" not in st.session_state:
    st.session_state.users = load_data()
if "username" not in st.session_state:
    st.session_state.username = None
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lock_time" not in st.session_state:
    st.session_state.lock_time = 0

# -------------------- UI --------------------
st.title("🛡️ Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# -------------------- Pages --------------------
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("This app allows you to securely store and retrieve text data using a unique passkey.")

elif choice == "Register":
    st.subheader("📝 Register")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user and new_pass:
            if new_user in st.session_state.users:
                st.error("User already exists!")
            else:
                st.session_state.users[new_user] = {
                    "password": hash_passkey(new_pass),
                    "data": {}
                }
                save_data(st.session_state.users)
                st.success("User registered successfully!")
        else:
            st.warning("Please provide username and password.")

elif choice == "Login":
    st.subheader("🔐 Login")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    if st.button("Login"):
        user_data = st.session_state.users.get(user)
        if user_data and user_data["password"] == hash_passkey(pwd):
            st.session_state.username = user
            st.session_state.authenticated = True
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials!")

elif choice == "Store Data":
    if st.session_state.authenticated:
        st.subheader("📂 Store Your Data")
        text = st.text_area("Enter data to encrypt:")
        passkey = st.text_input("Enter passkey for this data:", type="password")

        if st.button("Encrypt & Store"):
            if text and passkey:
                encrypted = cipher.encrypt(text.encode()).decode()
                hashed_passkey = hash_passkey(passkey)
                st.session_state.users[st.session_state.username]["data"][encrypted] = hashed_passkey
                save_data(st.session_state.users)
                st.success("Data encrypted and stored!")
                st.code(encrypted)
            else:
                st.error("Provide both text and passkey.")
    else:
        st.warning("Login required to store data.")

elif choice == "Retrieve Data":
    if st.session_state.authenticated:
        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
            elapsed = time.time() - st.session_state.lock_time
            if elapsed < COOLDOWN_TIME:
                st.warning(f"Too many failed attempts. Try again in {int(COOLDOWN_TIME - elapsed)} seconds.")
                st.stop()
            else:
                st.session_state.failed_attempts = 0

        st.subheader("🔍 Retrieve Data")
        encrypted_text = st.text_area("Paste encrypted data:")
        passkey = st.text_input("Enter passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                stored_data = st.session_state.users[st.session_state.username]["data"]
                stored_hash = stored_data.get(encrypted_text)

                if stored_hash and stored_hash == hash_passkey(passkey):
                    try:
                        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                        st.success("Decrypted successfully!")
                        st.code(decrypted)
                        st.session_state.failed_attempts = 0
                    except Exception:
                        st.error("Decryption error. Data may be corrupted.")
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.session_state.lock_time = time.time()
                        st.warning("Too many failed attempts. Locking for 30 seconds.")
                    else:
                        remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                        st.error(f"Incorrect passkey. {remaining} attempts left.")
            else:
                st.error("Provide both encrypted text and passkey.")
    else:
        st.warning("Login required to retrieve data.")

elif choice == "Logout":
    st.session_state.username = None
    st.session_state.authenticated = False
    st.success("Logged out.")
