import json
from pathlib import Path

#directory of the current script and the file path
SCRIPT_DIR = Path(__file__).parent
FILE_PATH = SCRIPT_DIR / "data\info.json"


def load_credentials():
    #load credentials from json if file found
    try:
        with FILE_PATH.open("r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: File not found or invalid JSON format.")
        return None

def login():
    #login if credentials exist
    credentials = load_credentials()
    if not credentials:
        print("No saved credentials found. Please sign up first.")
        return
    curUsername = input("Enter your username: ")
    curPassword = input("Enter your password: ")
    if curUsername == credentials.get("username") and curPassword == credentials.get("password"):
        print("Login successful!")
    else:
        print("Invalid username or password.")

def save_credentials():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    credentials = {
        "username": username,
        "password": password
    }
    with FILE_PATH.open("w") as file:
        json.dump(credentials, file, indent=4)
    print("Credentials saved successfully!")

# Example usage
while True:
    choice = input("Do you want to [L]ogin or [S]ign up? (L/S): ").strip().lower()
    
    if choice == "l":
        login()
    elif choice == "s":
        save_credentials()
    else:
        print("Invalid choice. Please enter 'L' to login or 'S' to sign up.")
