import json
import bcrypt
from pathlib import Path
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

# directory of the current script and the file path
SCRIPT_DIR = Path(__file__).parent
FILE_PATH = SCRIPT_DIR / "data\info.json"

# Connect to SQLite database
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# create a table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()


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
    cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user and verify_password(user[1], password):
        user_id = user[0]
        show_pineapple_question(user_id)
    else:
        messagebox.showerror("Error", "Invalid username or password.")

def save_credentials(username, password):
    hashed = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        messagebox.showinfo("Success", "Account created successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists. Please choose a different one.")

def on_signup():
    username = entry_username.get()
    password = entry_password.get()
    save_credentials(username, password)

def on_login():
    username = entry_username.get()
    password = entry_password.get()
    login(username, password)

def on_closing():
    conn.close()
    window.destroy()

def show_pineapple_question(user_id):
    for widget in frame.winfo_children():
        widget.destroy()
    ttk.Label(frame, text="Do you like pineapple on pizza?", font=("Arial", 14)).pack(pady=10)
    pineapple_var = tk.IntVar(value=-1)
    ttk.Radiobutton(frame, text="Yes", variable=pineapple_var, value=1).pack(pady=5)
    ttk.Radiobutton(frame, text="No", variable=pineapple_var, value=0).pack(pady=5)
    ttk.Button(frame, text="Submit", command=lambda: pineapple_submit(user_id, pineapple_var)).pack(pady=10)

def pineapple_submit(user_id, pineapple_var):
    selection = pineapple_var.get()
    if selection not in (0, 1):
        messagebox.showerror("Error", "Please select an option.")
        return
    # Here you could update the user's decision in the database if needed.
    # For example, add a new column to the table and update it.
    messagebox.showinfo("Preference Saved", "Your preference has been saved!")
    for widget in frame.winfo_children():
        widget.destroy()
    ttk.Label(frame, text="Thank you!", font=("Arial", 14)).pack(pady=20)

# GUI Setup
window = tk.Tk()
window.title("Modern Login System")
window.geometry("500x400")
window.resizable(False, False)

frame = ttk.Frame(window, padding=30)
frame.pack(expand=True)

ttk.Label(frame, text="Username:").pack(pady=5)
entry_username = ttk.Entry(frame)
entry_username.pack(pady=5)

ttk.Label(frame, text="Password:").pack(pady=5)
entry_password = ttk.Entry(frame, show="*")
entry_password.pack(pady=5)

ttk.Button(frame, text="Login", command=on_login).pack(pady=10)
ttk.Button(frame, text="Sign Up", command=on_signup).pack(pady=5)

window.protocol("WM_DELETE_WINDOW", on_closing)

window.mainloop()