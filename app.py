from time import sleep
from datetime import datetime
import json
import os
import streamlit as st
import random
import string
import re
import smtplib
import hashlib
from deep_translator import GoogleTranslator
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib
import base64
import pickle
import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

load_dotenv()
session_state = st.session_state
if "is_running" not in st.session_state:
    st.session_state.is_running = False
if "sample_data" not in st.session_state:
    st.session_state.sample_data = pd.read_csv("sample_data.csv")
if "user_index" not in st.session_state:
    st.session_state["user_index"] = 0

st.set_page_config(
    page_title="Secure Multilingual Communication Platform with Real-Time Translation and Advanced Cryptographic Security",
    page_icon="favicon.ico",
    layout="wide",
    initial_sidebar_state="expanded",
)


def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return (private_key, private_key.public_key())

def sign(message, private_key):
    message = message.encode('utf-8')
    padding_instance = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    return base64.b64encode(private_key.sign(message, padding_instance, hashes.SHA256())).hex()

def verify(message, signature, public_key):
    message = message.encode('utf-8')
    signature = base64.b64decode(bytes.fromhex(str(signature)))
    padding_instance = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    try:
        public_key.verify(signature, message, padding_instance, hashes.SHA256())
        return True
    except cryptography.exceptions.InvalidSignature:
        return False
    
def AES_encrypt(plaintext,aes_key):
    aes_key = bytes.fromhex(str(aes_key))
    plaintext = base64.b64encode(plaintext.encode())
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    ciphertext = str(cipher.nonce.hex()) + str(tag.hex()) + str(ciphertext.hex())
    return ciphertext


def AES_decrypt(ciphertext,aes_key):
    aes_key = bytes.fromhex(str(aes_key))
    nonce = ciphertext[:32]
    tag = ciphertext[32:64]
    ciphertext = ciphertext[64:]
    nonce = bytes.fromhex(str(nonce))
    tag = bytes.fromhex(str(tag))
    ciphertext = bytes.fromhex(str(ciphertext))
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    plaintext = base64.b64decode(plaintext).decode()
    return plaintext


def user_exists(email, json_file_path):
    # Function to check if user with the given email exists
    with open(json_file_path, "r") as file:
        users = json.load(file)
        for user in users["users"]:
            if user["email"] == email:
                return True
    return False


def send_verification_code(email, code):
    SENDER_MAIL_ID = os.getenv("SENDER_MAIL_ID")
    APP_PASSWORD = os.getenv("APP_PASSWORD")
    RECEIVER = email
    server = smtplib.SMTP_SSL("smtp.googlemail.com", 465)
    server.login(SENDER_MAIL_ID, APP_PASSWORD)
    message = f"Subject: Your Verification Code\n\nYour verification code is: {code}"
    server.sendmail(SENDER_MAIL_ID, RECEIVER, message)
    server.quit()
    st.success("Email sent successfully!")
    return True


def generate_verification_code(length=6):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def signup(json_file_path="data.json"):
    st.title("Signup Page")
    with st.form("signup_form"):
        st.write("Fill in the details below to create an account:")
        name = st.text_input("Name:")
        email = st.text_input("Email:")
        age = st.number_input("Age:", min_value=0, max_value=120)
        sex = st.radio("Sex:", ("Male", "Female", "Other"))
        password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")
        if st.form_submit_button("Signup"):
            if not name:
                st.error("Name field cannot be empty.")
            elif not email:
                st.error("Email field cannot be empty.")
            elif not re.match(r"^[\w\.-]+@[\w\.-]+$", email):
                st.error("Invalid email format. Please enter a valid email address.")
            elif user_exists(email, json_file_path):
                st.error(
                    "User with this email already exists. Please choose a different email."
                )
            elif not age:
                st.error("Age field cannot be empty.")
            elif not password or len(password) < 6:  # Minimum password length of 6
                st.error("Password must be at least 6 characters long.")
            elif password != confirm_password:
                st.error("Passwords do not match. Please try again.")
            else:
                user = create_account(
                        name,
                        email,
                        age,
                        sex,
                        password,
                        json_file_path,
                    )
                session_state["logged_in"] = True
                session_state["user_info"] = user
                st.success("Signup successful. You are now logged in!")



def check_login(username, password, json_file_path="data.json"):
    try:
        with open(json_file_path, "r") as json_file:
            data = json.load(json_file)

        for user in data["users"]:
            if user["email"] == username and user["password"] == password:
                session_state["logged_in"] = True
                session_state["user_info"] = user
                st.success("Login successful!")
                return user
        return None
    except Exception as e:
        st.error(f"Error checking login: {e}")
        return None


def initialize_database(json_file_path="data.json"):
    try:
        if not os.path.exists(json_file_path):
            data = {"users": []}
            with open(json_file_path, "w") as json_file:
                json.dump(data, json_file)
        if not os.path.exists("chats.json"):
            chats = {"chats": []}
            with open("chats.json", "w") as file:
                json.dump(chats, file)

    except Exception as e:
        print(f"Error initializing database: {e}")


def create_account(
    name, email, age, sex, password, json_file_path="data.json"
):
    try:
        if not os.path.exists(json_file_path) or os.stat(json_file_path).st_size == 0:
            data = {"users": []}
        else:
            with open(json_file_path, "r") as json_file:
                data = json.load(json_file)

        # Append new user data to the JSON structure
        email = email.lower()
        password = hashlib.md5(password.encode()).hexdigest()
        private_key, public_key = rsa_keypair()
        user_info = {
            "name": name,
            "email": email,
            "age": age,
            "sex": sex,
            "password": password,
            "private_key": private_key.private_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8, encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()).decode(),
            "public_key": public_key.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM, format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "chats": None,
        }

        data["users"].append(user_info)

        with open(json_file_path, "w") as json_file:
            json.dump(data, json_file, indent=4)

        st.success("Account created successfully! You can now login.")
        return user_info
    except json.JSONDecodeError as e:
        st.error(f"Error decoding JSON: {e}")
        return None
    except Exception as e:
        st.error(f"Error creating account: {e}")
        return None


def login(json_file_path="data.json"):
    st.title("Login Page")
    username = st.text_input("Email:")
    password = st.text_input("Password:", type="password")
    password = hashlib.md5(password.encode()).hexdigest()
    username = username.lower()

    login_button = st.button("Login")

    if login_button:
        user = check_login(username, password, json_file_path)
        if user is not None:
            session_state["logged_in"] = True
            session_state["user_info"] = user
        else:
            st.error("Invalid credentials. Please try again.")


def get_user_info(email, json_file_path="data.json"):
    try:
        with open(json_file_path, "r") as json_file:
            data = json.load(json_file)
            for user in data["users"]:
                if user["email"] == email:
                    return user
        return None
    except Exception as e:
        st.error(f"Error getting user information: {e}")
        return None


def render_dashboard(user_info, json_file_path="data.json"):
    try:
        st.title(f"Welcome to the Dashboard, {user_info['name']}!")
        st.subheader("User Information:")
        st.write(f"Name: {user_info['name']}")
        st.write(f"Sex: {user_info['sex']}")
        st.write(f"Age: {user_info['age']}")

    except Exception as e:
        st.error(f"Error rendering dashboard: {e}")


def main():
    st.title("Secure Multilingual Communication Platform with Real-Time Translation and Advanced Cryptographic Security")
    page = st.sidebar.radio(
        "Go to",
        (
            "Signup/Login",
            "Dashboard",
            "Chat",
            "Intrusion Detection App"
        ),
        key="page",
    )

    if page == "Signup/Login":
        st.title("Signup/Login Page")
        login_or_signup = st.radio(
            "Select an option", ("Login", "Signup"), key="login_signup"
        )
        if login_or_signup == "Login":
            login()
        else:
            signup()

    elif page == "Dashboard":
        if session_state.get("logged_in"):
            render_dashboard(session_state["user_info"])
        else:
            st.warning("Please login/signup to view the dashboard.")

    elif page == "Chat":
        if session_state.get("logged_in"):

            st.title("Chat Page")
            user_info = session_state["user_info"]
            with open("data.json", "r") as file:
                data = json.load(file)

            # Dropdown for selecting a user to chat with
            user_list = [
                user["name"]
                for user in data["users"]
                if user["email"] != user_info["email"]
            ]
            user_list.insert(0, "Select a user")
            selected_user = st.selectbox("Select a user to chat with:", user_list)

            # Language selection for translation
            language_mapping = {
                "English": "en",
                "Spanish": "es",
                "Japanese": "ja",
                "French": "fr",
                "German": "de",
                "Chinese": "zh-CN",
            }
            language_list = list(language_mapping.keys())
            selected_language = st.selectbox("Select your language:", language_list, key="lang_select")

            if selected_user != "Select a user":
                selected_user_info = [
                    user for user in data["users"] if user["name"] == selected_user
                ][0]
                st.write(f"Chatting with {selected_user_info['name']}...")

                with open("chats.json", "r") as file:
                    chats = json.load(file)

                chat_exists = False
                for chat in chats["chats"]:
                    if (
                        chat["user1"] == user_info["email"]
                        and chat["user2"] == selected_user_info["email"]
                    ) or (
                        chat["user1"] == selected_user_info["email"]
                        and chat["user2"] == user_info["email"]
                    ):
                        chat_exists = True
                        previous_chats = chat

                if not chat_exists:
                    chat_history = []
                    chats["chats"].append(
                        {
                            "user1": user_info["email"],
                            "user2": selected_user_info["email"],
                            "aes_key": get_random_bytes(16).hex(),
                            "chat_history": chat_history,
                        }
                    )
                    previous_chats = chats["chats"][-1]

                # Display previous chat messages
                if len(previous_chats["chat_history"]) > 0:
                    for chat in previous_chats["chat_history"]:
                        if chat["sender"] == user_info["name"]:
                            try:
                                # Decrypt and translate the message to the selected language
                                message = AES_decrypt(chat["message"], previous_chats["aes_key"])
                                translated_message = GoogleTranslator(
                                    source="en", target=language_mapping[selected_language]
                                ).translate(message)
                                st.chat_message("You", avatar="👩‍🎨").write(translated_message)
                            except Exception as e:
                                st.error("Message has been tampered with")
                        else:
                            public_key = serialization.load_pem_public_key(
                                selected_user_info["public_key"].encode(),
                                backend=default_backend()
                            )
                            if verify(chat["message"], chat["signature"], public_key):
                                try:
                                    # Decrypt and translate the message to the selected language
                                    message = AES_decrypt(chat["message"], previous_chats["aes_key"])
                                    translated_message = GoogleTranslator(
                                        source="en", target=language_mapping[selected_language]
                                    ).translate(message)
                                    st.chat_message(
                                        selected_user_info["name"], avatar="🤖"
                                    ).write(translated_message)
                                except Exception as e:
                                    st.error("Message translation failed")
                            else:
                                st.error("Invalid signature")

                # Input field for sending messages
                message = st.chat_input(f"Say something in {selected_language}")
                if message:
                    # Translate the message from the selected language to English before encryption
                    translated_message = GoogleTranslator(
                        source=language_mapping[selected_language], target="en"
                    ).translate(message)
                    ciphertext = AES_encrypt(translated_message, previous_chats["aes_key"])
                    private_key = user_info["private_key"].encode("utf-8")
                    private_key = serialization.load_pem_private_key(
                        private_key,
                        password=None,
                        backend=default_backend()
                    )
                    signature = sign(ciphertext, private_key)
                    previous_chats["chat_history"].append(
                        {"sender": user_info["name"], "message": ciphertext, "signature": signature}
                    )

                    # Update the chat history
                    for chat in chats["chats"]:
                        if (
                            chat["user1"] == user_info["email"]
                            and chat["user2"] == selected_user_info["email"]
                        ) or (
                            chat["user1"] == selected_user_info["email"]
                            and chat["user2"] == user_info["email"]
                        ):
                            chat = previous_chats

                    with open("chats.json", "w") as file:
                        json.dump(chats, file, indent=4)
                    st.rerun()
        else:
            st.warning("Please login/signup to access this page")

    elif page == "Intrusion Detection App":
        if session_state.get("logged_in"):
            st.markdown(
                "<h1 style='color:blue;'>Intrusion Detection App</h1>",
                unsafe_allow_html=True,
            )
            st.write("Click below to start predicting if their is an Intrusion or not:")

            # Display the saved image
            st.image("img1.png", use_column_width=True)

            X_1 = pd.read_csv("sample_data.csv")
            with open("random_model1.pkl", "rb") as f:
                model = pickle.load(f)

            start_button_clicked = st.button(
                "Start", key="start_button", help="Click to start predicting"
            )
            stop_button_clicked = st.button(
                "Stop", key="stop_button", help="Click to stop predicting"
            )
            data_heading = st.empty()
            data_placeholder = st.empty()
            prediction_placeholder = st.empty()

            def process_csv_with_delay(sampled_data, model, st):
                while st.session_state.is_running:

                    if len(sampled_data) == 0:
                        sampled_data = pd.read_csv("sample_data.csv")
                        continue

                    row = sampled_data.iloc[0]
                    prediction = model.predict([row])
                    headings = [
                        "Flow Duration",
                        "Total Fwd Packets",
                        "Total Backward Packets",
                        "Total Length of Fwd Packets",
                        "Total Length of Bwd Packets",
                        "Fwd Packet Length Max",
                        "Fwd Packet Length Min",
                        "Fwd Packet Length Mean",
                        "Fwd Packet Length Std",
                        "Bwd Packet Length Max",
                        "Bwd Packet Length Min",
                        "Bwd Packet Length Mean",
                        "Bwd Packet Length Std",
                        "Flow Bytes/s",
                        "Flow Packets/s",
                        "Flow IAT Mean",
                        "Flow IAT Std",
                        "Flow IAT Max",
                        "Flow IAT Min",
                        "Fwd IAT Total",
                        "Fwd IAT Mean",
                        "Fwd IAT Std",
                        "Fwd IAT Max",
                        "Fwd IAT Min",
                        "Bwd IAT Total",
                        "Bwd IAT Mean",
                        "Bwd IAT Std",
                        "Bwd IAT Max",
                        "Bwd IAT Min",
                        "Fwd PSH Flags",
                        "Bwd PSH Flags",
                        "Fwd URG Flags",
                        "Bwd URG Flags",
                        "Fwd Header Length",
                        "Bwd Header Length",
                        "Fwd Packets/s",
                        "Bwd Packets/s",
                        "Min Packet Length",
                        "Max Packet Length",
                        "Packet Length Mean",
                        "Packet Length Std",
                        "Packet Length Variance",
                        "FIN Flag Count",
                        "SYN Flag Count",
                        "RST Flag Count",
                        "PSH Flag Count",
                        "ACK Flag Count",
                        "URG Flag Count",
                        "CWE Flag Count",
                        "ECE Flag Count",
                        "Down/Up Ratio",
                        "Average Packet Size",
                        "Avg Fwd Segment Size",
                        "Avg Bwd Segment Size",
                        "Fwd Header Length.1",
                        "Fwd Avg Bytes/Bulk",
                        "Fwd Avg Packets/Bulk",
                        "Fwd Avg Bulk Rate",
                        "Bwd Avg Bytes/Bulk",
                        "Bwd Avg Packets/Bulk",
                        "Bwd Avg Bulk Rate",
                        "Subflow Fwd Packets",
                        "Subflow Fwd Bytes",
                        "Subflow Bwd Packets",
                        "Subflow Bwd Bytes",
                        "Init_Win_bytes_forward",
                        "Init_Win_bytes_backward",
                        "act_data_pkt_fwd",
                        "min_seg_size_forward",
                        "Active Mean",
                        "Active Std",
                        "Active Max",
                        "Active Min",
                        "Idle Mean",
                        "Idle Std",
                        "Idle Max",
                        "Idle Min",
                    ]
                    row = dict(zip(headings, row))
                    data_heading.markdown(
                        "<h2 style='color:blue;'>Network Data</h2>",
                        unsafe_allow_html=True,
                    )
                    data_placeholder.dataframe(row)
                    # Print the result with timestamp
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    if prediction[0] != "BENIGN":
                        prediction_placeholder.markdown(
                            f"<p style='color:red; font-size:20px;'>Time : {timestamp} - Danger !!! You are Under Attack ----> Attack Type: {prediction[0]} </p>",
                            unsafe_allow_html=True,
                        )
                    else:
                        prediction_placeholder.markdown(
                            f"<p style='color:green; font-size:20px;'>Time: {timestamp} - No attack detected</p>",
                            unsafe_allow_html=True,
                        )

                    sampled_data = sampled_data.iloc[1:]
                    st.session_state.sampled_data = (
                        sampled_data.to_json()
                    )  # Store the updated sampled_data in session state
                    sleep(5)

                    if not st.session_state.is_running:
                        break

            if start_button_clicked:
                st.session_state.is_running = True
                process_csv_with_delay(X_1, model, st)

            if stop_button_clicked:
                st.session_state.is_running = False
    else:
        st.warning("Please login/signup to use the app!!")


if __name__ == "__main__":
    initialize_database()
    main()
