# This script checks torrents in qBittorrent and stops seeding those with a ratio >= 1.0
# It saves login credentials securely using encryption for future use

# Import necessary libraries
import qbittorrentapi  # For interacting with qBittorrent
import logging  # For logging script actions
from datetime import datetime  # For timestamping log entries
import getpass  # For securely inputting passwords
import os  # For checking if files exist and generating random bytes
import json  # For working with JSON data
import base64  # For encoding and decoding base64 data

# Import encryption-related functions from the cryptography library
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Set up logging - this will create a file to record what the script does
logging.basicConfig(filename='qbittorrent_checker.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# qBittorrent connection details
HOST = "localhost"  # The address of the qBittorrent WebUI
PORT = 8080  # The port of the qBittorrent WebUI
CREDENTIALS_FILE = "qbittorrent_credentials.json"  # File to store encrypted credentials
KEY_FILE = "encryption_key.key"  # File to store salt and verification key

# Function to derive an encryption key from a password and salt
def derive_key(password, salt):
    """Create an encryption key from a password and salt."""
    # Use PBKDF2HMAC to derive a key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA256 hash algorithm
        length=32,  # Derive a 32-byte key
        salt=salt,
        iterations=100000,  # Use 100,000 iterations (more is slower but more secure)
        backend=default_backend()
    )
    # Derive the key and encode it as base64
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to create a new encryption key
def create_key():
    """Create a new encryption key and save it to a file."""
    salt = os.urandom(16)  # Generate 16 random bytes for the salt
    password = getpass.getpass("Create a master password for encryption: ")
    key = derive_key(password, salt)  # Derive the key from the password and salt
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(salt + key)  # Save the salt and key to the file
    print("Created new encryption key.")

# Function to get the encryption key
def get_key():
    """Get the encryption key using the stored salt and user's password."""
    with open(KEY_FILE, "rb") as key_file:
        content = key_file.read()
        salt = content[:16]  # The first 16 bytes are the salt
        stored_key = content[16:]  # The rest is the stored key
    password = getpass.getpass("Enter your master password: ")
    derived_key = derive_key(password, salt)  # Derive the key from the entered password
    if derived_key != stored_key:
        raise ValueError("Incorrect password")  # If the derived key doesn't match, the password is wrong
    return derived_key

# Function to encrypt the credentials
def encrypt_credentials(username, password):
    """Encrypt the username and password."""
    key = get_key()  # Get the encryption key
    f = Fernet(key)  # Create a Fernet instance with the key
    # Convert credentials to JSON string, then to bytes, then encrypt
    credentials = json.dumps({"username": username, "password": password}).encode()
    return f.encrypt(credentials)

# Function to decrypt the credentials
def decrypt_credentials(encrypted_credentials):
    """Decrypt the encrypted credentials."""
    key = get_key()  # Get the encryption key
    f = Fernet(key)  # Create a Fernet instance with the key
    # Decrypt the credentials, convert from bytes to string, then parse JSON
    decrypted_credentials = f.decrypt(encrypted_credentials)
    return json.loads(decrypted_credentials.decode())

# Function to save credentials to a file
def save_credentials(username, password):
    """Save encrypted credentials to a file."""
    encrypted_credentials = encrypt_credentials(username, password)
    with open(CREDENTIALS_FILE, "wb") as file:
        file.write(encrypted_credentials)  # Write encrypted credentials to file
    print("Saved credentials for future use.")

# Function to load credentials from a file
def load_credentials():
    """Load and decrypt credentials from the file."""
    with open(CREDENTIALS_FILE, "rb") as file:
        encrypted_credentials = file.read()  # Read encrypted credentials from file
    return decrypt_credentials(encrypted_credentials)

# Function to get credentials from user input
def get_user_credentials():
    """Ask the user for their qBittorrent WebUI username and password."""
    print("Please enter your qBittorrent WebUI credentials.")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()  # getpass hides the password when typing
    return username, password

# Function to check torrents and stop seeding if ratio >= 1.0
def check_and_stop_torrents(username, password):
    """Check torrents and stop seeding those with ratio >= 1.0"""
    try:
        # Try to connect to qBittorrent
        qbt_client = qbittorrentapi.Client(host=HOST, port=PORT, username=username, password=password)
        qbt_client.auth_log_in()
        logging.info("Successfully logged in to qBittorrent")
        print("Successfully logged in to qBittorrent")
    except Exception as e:
        # If connection fails, log the error and exit the function
        logging.error(f"Failed to connect to qBittorrent: {e}")
        print(f"Failed to connect to qBittorrent: {e}")
        return

    # Get list of all torrents
    all_torrents = qbt_client.torrents_info()
    logging.info(f"Found {len(all_torrents)} torrents")
    print(f"Found {len(all_torrents)} torrents")

    # Check each torrent
    for torrent in all_torrents:
        # If the torrent's ratio is 1.0 or higher
        if torrent.ratio >= 1.0:
            try:
                # Stop seeding this torrent
                qbt_client.torrents_pause(torrent_hashes=torrent.hash)
                logging.info(f"Stopped seeding: {torrent.name} (Ratio: {torrent.ratio:.2f})")
                print(f"Stopped seeding: {torrent.name} (Ratio: {torrent.ratio:.2f})")
            except Exception as e:
                # If stopping fails, log the error
                logging.error(f"Couldn't stop {torrent.name}: {e}")
                print(f"Couldn't stop {torrent.name}: {e}")

    # Log out from qBittorrent
    qbt_client.auth_log_out()
    logging.info("Logged out from qBittorrent")
    print("Logged out from qBittorrent")

# This is where the script starts running
if __name__ == "__main__":
    logging.info("Starting the qBittorrent checker script")
    print("Starting the qBittorrent checker script")

    # Check if encryption key exists, if not, create one
    if not os.path.exists(KEY_FILE):
        create_key()

    # Check if credentials file exists
    if not os.path.exists(CREDENTIALS_FILE):
        # If no credentials file, ask user for credentials and save them
        username, password = get_user_credentials()
        save_credentials(username, password)
    else:
        try:
            # Try to load existing credentials
            credentials = load_credentials()
            username = credentials['username']
            password = credentials['password']
            print("Loaded saved credentials.")
        except Exception as e:
            # If loading fails, ask for new credentials
            logging.error(f"Failed to load credentials: {e}")
            print(f"Failed to load credentials: {e}")
            username, password = get_user_credentials()
            save_credentials(username, password)

    # Run the main function to check and stop torrents
    check_and_stop_torrents(username, password)

    logging.info("Finished the qBittorrent checker script")
    print("Finished the qBittorrent checker script")
