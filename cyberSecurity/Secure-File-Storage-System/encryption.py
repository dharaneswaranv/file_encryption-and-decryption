# # encryption.py
# from cryptography.fernet import Fernet

# def load_key():
#     """Load the encryption key from a file."""
#     with open("secret.key", "rb") as key_file:
#         key = key_file.read()
#     return key

# def generate_key():
#     """Generate a new encryption key and save it to a file."""
#     key = Fernet.generate_key()
#     with open("secret.key", "wb") as key_file:
#         key_file.write(key)
#     print("Encryption key generated successfully.")

# def encrypt_file(file_path):
#     """Encrypt the contents of a file."""
#     key = load_key()
#     fernet = Fernet(key)
#     with open(file_path, "rb") as file:
#         file_data = file.read()
#     encrypted_data = fernet.encrypt(file_data)
#     with open(file_path, "wb") as file:
#         file.write(encrypted_data)
#     print(f"File '{file_path}' encrypted successfully.")

# def decrypt_file(file_path):
#     """Decrypt the contents of a file."""
#     key = load_key()
#     fernet = Fernet(key)
#     with open(file_path, "rb") as file:
#         encrypted_data = file.read()
#     decrypted_data = fernet.decrypt(encrypted_data)
#     with open(file_path, "wb") as file:
#         file.write(decrypted_data)
#     print(f"File '{file_path}' decrypted successfully.")

# encryption.py
# -----------------------------------
# from cryptography.fernet import Fernet
# import os
# import base64
# import json
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# # Constants
# KEY_FILE = 'secret.key'
# METADATA_FILE = 'metadata.json'
# LOG_FILE = 'logs/operations.log'

# def load_key():
#     """Load the encryption key from the key file."""
#     if not os.path.exists(KEY_FILE):
#         raise FileNotFoundError("Encryption key not found. Run setup.py to generate one.")
#     with open(KEY_FILE, 'rb') as key_file:
#         key = key_file.read()
#     return key

# def generate_key(password: str):
#     """Generate a key based on a password."""
#     password = password.encode()  # Convert password to bytes
#     salt = b'\x00' * 16  # Use a static salt for simplicity (not recommended for production)
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#     )
#     key = base64.urlsafe_b64encode(kdf.derive(password))
#     with open(KEY_FILE, 'wb') as key_file:
#         key_file.write(key)
#     print("Key generated and saved to", KEY_FILE)

# def encrypt_file(file_path: str, password: str):
#     """Encrypt a file with the provided password."""
#     key = load_key()
#     cipher = Fernet(key)
    
#     with open(file_path, 'rb') as file:
#         file_data = file.read()
#     encrypted_data = cipher.encrypt(file_data)
    
#     with open(file_path + '.enc', 'wb') as file:
#         file.write(encrypted_data)

#     log_operation(f"File encrypted: {file_path}")

# def decrypt_file(file_path: str, password: str):
#     """Decrypt a file with the provided password."""
#     key = load_key()
#     cipher = Fernet(key)
    
#     with open(file_path, 'rb') as file:
#         encrypted_data = file.read()
#     decrypted_data = cipher.decrypt(encrypted_data)
    
#     with open(file_path.replace('.enc', ''), 'wb') as file:
#         file.write(decrypted_data)

#     log_operation(f"File decrypted: {file_path}")

# def log_operation(message: str):
#     """Log operations to a file."""
#     with open(LOG_FILE, 'a') as log_file:
#         log_file.write(message + '\n')

from cryptography.fernet import Fernet
import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
KEY_FILE = 'secret.key'
METADATA_FILE = 'metadata.json'
LOG_FILE = 'logs/operations.log'

def load_key(password: str):
    """Generate a key based on the provided password."""
    password = password.encode()  # Convert password to bytes
    salt = b'\x00' * 16  # Use a static salt for simplicity (not recommended for production)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def generate_key(password: str):
    """Generate a key and save it to the key file."""
    key = load_key(password)
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    print("Key generated and saved to", KEY_FILE)

def encrypt_file(file_path: str, password: str):
    """Encrypt a file with the provided password."""
    key = load_key(password)
    cipher = Fernet(key)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    
    with open(file_path + '.enc', 'wb') as file:
        file.write(encrypted_data)

    log_operation(f"File encrypted: {file_path}")

def decrypt_file(file_path: str, password: str):
    """Decrypt a file with the provided password."""
    key = load_key(password)
    cipher = Fernet(key)
    
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    
    with open(file_path.replace('.enc', ''), 'wb') as file:
        file.write(decrypted_data)

    log_operation(f"File decrypted: {file_path}")

def log_operation(message: str):
    """Log operations to a file."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)  # Ensure log directory exists
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(message + '\n')
