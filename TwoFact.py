import json
import bcrypt
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

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

def login(username, password):
    # login if credentials exist
    credentials = load_credentials()
    
    for user in credentials.values():
        if user["username"] == username and verify_password(user["password"], password):
            messagebox.showinfo("Success", "Login successful!")
            return
    
    messagebox.showerror("Error", "Invalid username or password.")

def save_credentials(username, password):
    credentials = load_credentials()
    
    if any(user["username"] == username for user in credentials.values()):
        messagebox.showerror("Error", "Username already exists. Please choose a different one.")
        return

    primary_key = str(max(map(int, credentials.keys())) + 1) if credentials else "1" # add unique primary key to everyone
    credentials[primary_key] = {"username": username, "password": hash_password(password)}
    
    with FILE_PATH.open("w") as file:
        json.dump(credentials, file, indent=4)
    
    messagebox.showinfo("Success", "Account created successfully!")


def on_signup():
    username = entry_username.get()
    password = entry_password.get()
    save_credentials(username, password)

def on_login():
    username = entry_username.get()
    password = entry_password.get()
    login(username, password)

# GUI setup
root = tk.Tk()
root.title("Login System")
root.geometry("300x200")

tk.Label(root, text="Username:").pack()
entry_username = tk.Entry(root)
entry_username.pack()

tk.Label(root, text="Password:").pack()
entry_password = tk.Entry(root, show="*")
entry_password.pack()

tk.Button(root, text="Login", command=on_login).pack()
tk.Button(root, text="Sign Up", command=on_signup).pack()

root.mainloop()
