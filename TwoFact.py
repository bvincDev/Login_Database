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
    """
    Clears the login UI and builds a new interface that asks
    "Do you like pineapple on pizza?" with radio buttons for Yes/No.
    """
    # Clear all widgets in the frame
    for widget in frame.winfo_children():
        widget.destroy()

    # Create a label for the question
    label = tk.Label(frame, text="Do you like pineapple on pizza?", font=("Arial", 14), bg="#f2f2f2")
    label.pack(pady=10)

    # Create an IntVar to hold the radio button selection (1 for Yes, 0 for No)
    pineapple_var = tk.IntVar(value=-1)  # -1 indicates no selection yet

    # Create the radio buttons
    radio_yes = tk.Radiobutton(frame, text="Yes", variable=pineapple_var, value=1,
                               font=("Arial", 14), bg="#f2f2f2")
    radio_no = tk.Radiobutton(frame, text="No", variable=pineapple_var, value=0,
                              font=("Arial", 14), bg="#f2f2f2")
    radio_yes.pack(pady=5)
    radio_no.pack(pady=5)

    # Create a submit button that calls pineapple_submit with the user key and credentials dictionary
    submit_button = tk.Button(frame, text="Submit", font=("Arial", 14),
                              bg="#4CAF50", fg="white", width=15,
                              command=lambda: pineapple_submit(user_key, pineapple_var, credentials))
    submit_button.pack(pady=10)

def pineapple_submit(user_key, pineapple_var, credentials):
    """
    Called when the user submits their pineapple preference.
    Updates the user record in the JSON file with the selection.
    """
    selection = pineapple_var.get()
    if selection not in (0, 1):
        messagebox.showerror("Error", "Please select an option.")
        return

    # Store the preference in the user’s record as a boolean
    credentials[user_key]["decision"] = True if selection == 1 else False

    # Write the updated credentials back to the JSON file
    with FILE_PATH.open("w") as file:
        json.dump(credentials, file, indent=4)

    messagebox.showinfo("Preference Saved", "Your preference has been saved!")

    # (Optional) Clear the frame or show a final message
    for widget in frame.winfo_children():
        widget.destroy()
    final_label = tk.Label(frame, text="Thank you!", font=("Arial", 14), bg="#f2f2f2")
    final_label.pack(pady=20)


# GUI Setup
window = tk.Tk()
window.title("Login System")

# Fullscreen mode
window.attributes('-fullscreen', True)
window.bind("<Escape>", lambda event: window.attributes('-fullscreen', False), window.geometry("600x400"))  # Press esc to exit full screen and adjust window size

# # Windowed-fullscreen mode
# window.geometry("{}x{}+0+0". format(window.winfo_screenwidth(), window.winfo_screenheight()))

# Center Frame for UI
frame = tk.Frame(window, padx=40, pady=40, bg="#f2f2f2")
frame.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(frame, text="Username:", font=("Arial", 14), bg="#f2f2f2").pack(pady=5)
entry_username = tk.Entry(frame, font=("Arial", 14), width=20, bd=2, relief="solid")
entry_username.pack(pady=5)

tk.Label(frame, text="Password:", font=("Arial", 14), bg="#f2f2f2").pack(pady=5)
entry_password = tk.Entry(frame, show="*", font=("Arial", 14), width=20, bd=2, relief="solid")
entry_password.pack(pady=5)

tk.Button(frame, text="Login", command=on_login, font=("Arial", 14), bg="#4CAF50", fg="white", width=15).pack(pady=10)
tk.Button(frame, text="Sign Up", command=on_signup, font=("Arial", 14), bg="#008CBA", fg="white", width=15).pack(pady=5)

window.mainloop()