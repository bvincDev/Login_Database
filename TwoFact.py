import json
import bcrypt
import mysql.connector
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox


"""pyinstaller --onefile your_script.py     to create executable"""

# ---------------------------
# Password hashing functions
# ---------------------------
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

# ---------------------------
# Database connection helpers
# ---------------------------
def get_connection():
    # Update these parameters with your MySQL configuration
    return mysql.connector.connect(
        host="localhost",
        user="bvincDev",           # Your MySQL username
        password="",  # Your MySQL password
        database="infoDB" 
    )

def initialize_db():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                decision BOOLEAN
            )
        """)
        conn.commit()
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error initializing database: {err}")
    finally:
        cursor.close()
        conn.close()

# ---------------------------
# User authentication functions
# ---------------------------
def login(username, password):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user is None or not verify_password(user["password"], password):
            messagebox.showerror("Error", "Invalid username or password.")
            return
        # If login is successful, show the pineapple question UI
        show_pineapple_question(user["id"])
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")

def save_credentials(username, password):
    hashed = hash_password(password)
    try:
        conn = get_connection()
        cursor = conn.cursor()
        # Check if the username already exists
        cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cursor.fetchone() is not None:
            messagebox.showerror("Error", "Username already exists. Please choose a different one.")
            cursor.close()
            conn.close()
            return
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed))
        conn.commit()
        cursor.close()
        conn.close()
        messagebox.showinfo("Success", "Account created successfully!")
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")

# ---------------------------
# GUI callback functions
# ---------------------------
def on_signup():
    username = entry_username.get()
    password = entry_password.get()
    save_credentials(username, password)

def on_login():
    username = entry_username.get()
    password = entry_password.get()
    login(username, password)

def show_pineapple_question(user_id):
    for widget in content_frame.winfo_children():
        widget.destroy()
    ttk.Label(content_frame, text="Do you like pineapple on pizza?", style="Heading.TLabel").pack(pady=10)
    
    pineapple_var = tk.IntVar(value=-1)
    ttk.Radiobutton(content_frame, text="Yes", variable=pineapple_var, value=1, style="TRadiobutton").pack(pady=5)
    ttk.Radiobutton(content_frame, text="No", variable=pineapple_var, value=0, style="TRadiobutton").pack(pady=5)
    ttk.Button(content_frame, text="Submit", command=lambda: pineapple_submit(user_id, pineapple_var),
               style="TButton").pack(pady=10)

def pineapple_submit(user_id, pineapple_var):
    selection = pineapple_var.get()
    if selection not in (0, 1):
        messagebox.showerror("Error", "Please select an option.")
        return
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET decision=%s WHERE id=%s", (selection == 1, user_id))
        conn.commit()
        cursor.close()
        conn.close()
        messagebox.showinfo("Preference Saved", "Your preference has been saved!")
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")
        return
    for widget in content_frame.winfo_children():
         widget.destroy()
    ttk.Label(content_frame, text="Thank you!", style="Heading.TLabel").pack(pady=20)

# ---------------------------
# GUI Setup
# ---------------------------
window = tk.Tk()
window.title("Modern Login System")
window.geometry("500x400")
window.resizable(False, False)
window.configure(bg="#2c3e50")

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

# Buttons for Login and Sign Up
ttk.Button(content_frame, text="Login", command=on_login, style="TButton").pack(pady=10)
ttk.Button(content_frame, text="Sign Up", command=on_signup, style="TButton").pack(pady=5)

# Initialize the database (creates the table if it doesn't exist)
initialize_db()

window.mainloop()