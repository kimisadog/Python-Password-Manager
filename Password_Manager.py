from tkinter import *
from tkinter.ttk import Progressbar
import sqlite3
import hashlib

txtBox = None
strength_var = None  # Declare strength_var globally

# DB creation
with sqlite3.connect("Password_Manager.db") as db:
    cursor = db.cursor() 

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

# Creating the main window screen
window = Tk()
window.title("Password Manager")

def check_password_strength(password):
    if len(password) < 7:
        return "Weak"
    
    symbol_count = sum(1 for char in password if not char.isalnum())
    
    if symbol_count > 1:
        return "Strong"
    elif symbol_count == 1:
        return "Medium"
    
    if any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password):
        return "Strong"
    elif any(char.islower() for char in password) or any(char.isupper() for char in password) or any(char.isdigit() for char in password):
        return "Medium"
    else:
        return "Weak"

def update_strength(progress, *args):
    password = txtBox.get()
    strength = check_password_strength(password)
    strength_var.set("Password Strength: " + strength)

    if strength == "Weak":
        progress_color = "red"
    elif strength == "Medium":
        progress_color = "orange"
    else:
        progress_color = "green"

    # Update the color of the progress bar
    canvas.itemconfig(progress["bar"], fill=progress_color)

    # Update the length of the progress bar based on strength
    if strength == "Weak":
        progress_length = 30
    elif strength == "Medium":
        progress_length = 70
    else:
        progress_length = 200

    canvas.coords(progress["bar"], 0, 0, progress_length, 20)

# Function to save password to the database
def savePassword():
    if txtBox.get() == txtBox1.get():
        hashedpassword = hashlib.sha256(txtBox.get().encode("utf-8")).hexdigest()

        insert_password = """INSERT INTO masterpassword(password)
        VALUES(?) """
        cursor.execute(insert_password, [(hashedpassword)])
        db.commit()

        PasswordVault()
    else:
        label3.config(text="Passwords do not match")

# Function to check the master password
def getMasterPassword():
    checkHashedPassword = hashlib.sha256(txtBox.get().encode("utf-8")).hexdigest()
    cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkHashedPassword])
    return cursor.fetchall()

# Function to check the password entered by the user
def CheckPassword():
    match = getMasterPassword()
    if match:
        PasswordVault()
    else:
        txtBox.delete(0, "end")
        label5.config(text="Wrong Password") 

def Initial_Use():
    global txtBox, canvas, strength_var  # Add strength_var to the global variables
    window.geometry("400x200")   

    label = Label(window, text="Create Master Password")
    label.config(anchor=CENTER)
    label.pack()

    txtBox = Entry(window, width=30, show="*")
    txtBox.pack()
    txtBox.focus()

    label2 = Label(window, text="Re-enter Password")
    label2.pack()

    txtBox1 = Entry(window, width=30, show="*")
    txtBox1.pack()
    #txtBox1.focus()

    label3 = Label(window)
    label3.pack()

    # Progress bar for password strength
    strength_var = StringVar()
    strength_var.set("Password Strength: ")
    strength_label = Label(window, textvariable=strength_var)
    strength_label.pack()

    # Create a custom progress bar using a rectangle on the canvas
    canvas = Canvas(window, width=200, height=20)
    canvas.pack()

    # Create a custom progress bar using a rectangle on the canvas
    progress = {"value": 0, "bar": canvas.create_rectangle(0, 0, 0, 20, fill="green")}

    # Bind the update_strength function to the password entry
    txtBox.bind('<KeyRelease>', lambda event, progress=progress: update_strength(progress, event))

    # Bind the update_strength function to the second password entry
    txtBox1.bind('<KeyRelease>', lambda event, progress=progress: update_strength(progress, event))

    button = Button(window, text="Save", command=savePassword)
    button.pack()

def loginScreen():
    global txtBox, canvas, strength_var  # Add strength_var to the global variables
    window.geometry("400x200")
    
    label4 = Label(window, text="Enter your master password")
    label4.config(anchor=CENTER)
    label4.pack()

    txtBox = Entry(window, width=30, show="*")
    txtBox.pack()
    txtBox.focus()

    label5 = Label(window)
    label5.pack()

    button = Button(window, text="Confirm", command=CheckPassword)
    button.pack()

def PasswordVault():
    for widget in window.winfo_children():
        widget.destroy()
    
    window.geometry("700x350")
    
    label7 = Label(window, text="Password Vault")
    label7.config(anchor=CENTER)
    label7.pack()

# Check if a master password is already set
check = cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    Initial_Use() 

window.mainloop()
