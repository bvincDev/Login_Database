import json
import bcrypt
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

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
    credentials = load_credentials()
    # Loop through the credentials, keeping the key so we can update the user record later
    for user_key, user in credentials.items():
        if user["username"] == username and verify_password(user["password"], password):
            # Login successful: show the pineapple question UI instead of a messagebox
            show_pineapple_question(user_key, credentials)
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


def show_pineapple_question(user_key, credentials):
    for widget in content_frame.winfo_children():
        widget.destroy()
    ttk.Label(content_frame, text="Do you like pineapple on pizza?", style="Heading.TLabel").pack(pady=10)
    
    pineapple_var = tk.IntVar(value=-1)
    ttk.Radiobutton(content_frame, text="Yes", variable=pineapple_var, value=1, style="TRadiobutton").pack(pady=5)
    ttk.Radiobutton(content_frame, text="No", variable=pineapple_var, value=0, style="TRadiobutton").pack(pady=5)
    ttk.Button(content_frame, text="Submit", command=lambda: pineapple_submit(user_key, pineapple_var, credentials),
               style="TButton").pack(pady=10)

def pineapple_submit(user_key, pineapple_var, credentials):
    selection = pineapple_var.get()
    if selection not in (0, 1):
        messagebox.showerror("Error", "Please select an option.")
        return
    credentials[user_key]["decision"] = (selection == 1)
    with FILE_PATH.open("w") as file:
        json.dump(credentials, file, indent=4)
    messagebox.showinfo("Preference Saved", "Your preference has been saved!")
    for widget in content_frame.winfo_children():
        widget.destroy()
    ttk.Label(content_frame, text="Thank you!", style="Heading.TLabel").pack(pady=20)

# GUI Setup
window = tk.Tk()
window.title("Modern Login System")
window.geometry("500x400")
window.resizable(False, False)
window.configure(bg="#2c3e50")  # Dark background for the window

# Use the "clam" theme for a modern look
style = ttk.Style(window)
style.theme_use("clam")

# Configure widget styles for a sleek, modern design
style.configure("TFrame", background="#2c3e50")
style.configure("TLabel", background="#2c3e50", foreground="#ecf0f1", font=("Segoe UI", 12))
style.configure("Heading.TLabel", background="#2c3e50", foreground="#ecf0f1", font=("Segoe UI", 16, "bold"))
style.configure("TButton", font=("Segoe UI", 12), padding=10, background="#34495e", foreground="#ecf0f1")
style.map("TButton", background=[("active", "#3d566e")])
style.configure("TEntry", font=("Segoe UI", 12), padding=5)
style.configure("TRadiobutton", background="#2c3e50", foreground="#ecf0f1", font=("Segoe UI", 12))

# Main content frame
content_frame = ttk.Frame(window, padding=30, style="TFrame")
content_frame.pack(expand=True)

# Username field
ttk.Label(content_frame, text="Username:").pack(pady=(0, 5))
entry_username = ttk.Entry(content_frame, width=30, style="TEntry")
entry_username.pack(pady=(0, 10))

# Password field
ttk.Label(content_frame, text="Password:").pack(pady=(0, 5))
entry_password = ttk.Entry(content_frame, show="*", width=30, style="TEntry")
entry_password.pack(pady=(0, 10))

# Buttons
ttk.Button(content_frame, text="Login", command=on_login, style="TButton").pack(pady=10)
ttk.Button(content_frame, text="Sign Up", command=on_signup, style="TButton").pack(pady=5)

window.mainloop()