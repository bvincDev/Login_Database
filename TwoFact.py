import json
import bcrypt
from pathlib import Path

# directory of the current script and the file path
SCRIPT_DIR = Path(__file__).parent
FILE_PATH = SCRIPT_DIR / "data\info.json"


def hash_password(password):
    # use bcrypt to hash password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_password(stored_hash, password):
    # verify the password against the already stored
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def load_credentials():
    # load credentials from json if file found
    try:
        with FILE_PATH.open("r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} # empty disctionary if none is found

def login():
    # login if credentials exist
    credentials = load_credentials()
    if not credentials:
        print("No saved credentials found. Please sign up first.")
        return
    
    curUsername = input("Enter your username: ")
    curPassword = input("Enter your password: ")

    # Search through the dictionary values for the username and verify password
    for key, user in credentials.items():
        if user["username"] == curUsername and verify_password(user["password"], curPassword):
            print("Login successful!")
            return

def save_credentials():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    credentials = load_credentials()  # load existing credentials

    if credentials:
        primary_key = str(max(map(int, credentials.keys())) + 1) # add unique primary key to everyone
    else:
        primary_key = "1"

    
    if username in credentials:
        print("Error: Username already exists. Please choose a different one.")
        return

    credentials[primary_key] = {
        "username": username,
        "password": hash_password(password)  # Store hashed password
    }
    

    with FILE_PATH.open("w") as file:
        json.dump(credentials, file, indent=4)

    print("Credentials saved securely!")

# example usage
while True:
    choice = input("Do you want to [L]ogin or [S]ign up? (L/S): ").strip().lower()
    
    if choice == "l":
        login()
    elif choice == "s":
        save_credentials()
    else:
        print("Invalid choice. Please enter 'L' to login or 'S' to sign up.")
