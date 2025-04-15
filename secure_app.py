import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state to store variables across reruns
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"data_id": {"encrypted_text": "xyz", "passkey": "hashed"}}

if 'key' not in st.session_state:
    # Generate a key (this should be stored securely in production)
    st.session_state.key = Fernet.generate_key()

# Create cipher from the key
cipher = Fernet(st.session_state.key)

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    # Search for a matching entry in stored data
    for data_id, data_info in st.session_state.stored_data.items():
        if data_info["passkey"] == hashed_passkey and data_info["encrypted_text"] == encrypted_text:
            # If found, reset failed attempts and return decrypted text
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    # If no match was found, increment failed attempts
    st.session_state.failed_attempts += 1
    return None

# Function to generate a unique ID for data
def generate_data_id():
    import uuid
    return str(uuid.uuid4())

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]

# If too many failed attempts, force login page
if st.session_state.failed_attempts >= 3:
    choice = "Login"
else:
    choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    # Display additional information
    st.info("How it works:")
    st.write("1. Store your data with a unique passkey")
    st.write("2. The system encrypts and stores your data securely")
    st.write("3. Retrieve your data anytime using the correct passkey")
    st.write("4. After 3 failed attempts, you'll need to reauthorize")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            # Hash passkey for secure storage
            hashed_passkey = hash_passkey(passkey)
            
            # Encrypt user data
            encrypted_text = encrypt_data(user_data)
            
            # Generate unique ID for this data entry
            data_id = generate_data_id()
            
            # Store encrypted data with its hashed passkey
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted_text, 
                "passkey": hashed_passkey
            }
            
            st.success("✅ Data stored securely!")
            
            # Display the encrypted text for the user to save
            st.code(encrypted_text)
            st.info("⚠️ Save the encrypted text above to retrieve your data later!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # Show warning if previous attempts failed
    if st.session_state.failed_attempts > 0:
        st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")
    
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Decryption successful!")
                st.subheader("Your Decrypted Data:")
                st.write(decrypted_text)
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                
                # Check if max attempts reached
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    st.write("You've had too many failed attempts. Please reauthorize to continue.")
    
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        # For demonstration purposes, using a simple master password
        # In a real app, this should be properly secured
        if login_pass == "admin123":  
            # Reset failed attempts counter
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            
            # Redirect to retrieve data page
            st.experimental_set_query_params()
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")