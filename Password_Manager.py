from tkinter import *
from tkinter.ttk import Progressbar, Style, Treeview, Scrollbar, Button
import sqlite3
import hashlib
from ttkthemes import ThemedTk
from tkinter import simpledialog
from tkinter import ttk, messagebox

# Create the main window screen
window = ThemedTk(theme="plastik")
window.title("Password Manager")

# Global variables
txtBox = None
canvas = None
strength_var = None
progress = None  # Added progress as a global variable

# Database initialization
with sqlite3.connect("Password_Manager.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS passwordvault(
    id INTEGER PRIMARY KEY,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL);
""")

# Function to create a pop-up dialog
def popUp(title, text, initial_text=""):
    answer = simpledialog.askstring(title, text, initialvalue=initial_text)
    return answer

# Function to check password strength
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

# Function to update password strength
def update_strength(parent_frame, strength_var, password, progress):
    # Recreate widgets if they are None
    if strength_var is None:
        strength_var = StringVar()
        strength_var.set("Password Strength: ")
        strength_label = Label(parent_frame, textvariable=strength_var)
        strength_label.grid(row=2, column=4, pady=5, padx=5)

    if progress is None:
        progress = {"value": 0, "bar": parent_frame.create_rectangle(0, 0, 0, 10, fill="green")}

    # Rest of the function remains the same
    strength = check_password_strength(password)
    strength_var.set("Password Strength: " + strength)

    if strength == "Weak":
        progress_color = "red"
    elif strength == "Medium":
        progress_color = "orange"
    else:
        progress_color = "green"

    parent_frame.itemconfig(progress["bar"], fill=progress_color)
    progress_length = 30 if strength == "Weak" else 70 if strength == "Medium" else 200
    parent_frame.coords(progress["bar"], 0, 0, progress_length, 10)

# Function to save password to the database
def save_password():
    global txtBox, txtBox1, label3, canvas  # Add canvas as a global variable

    # Get the entered passwords
    password1 = txtBox.get()
    password2 = txtBox1.get()

    # Check if passwords match
    if password1 == password2:
        # Check password strength
        strength = check_password_strength(password1)

        # Check if password meets criteria
        if len(password1) >= 7 and any(char.isupper() for char in password1) and any(not char.isalnum() for char in password1):
            hashed_password = hashlib.sha256(password1.encode("utf-8")).hexdigest()

            insert_password = """INSERT INTO masterpassword(password)
                                 VALUES(?) """
            cursor.execute(insert_password, [(hashed_password)])
            db.commit()

            password_vault()
        else:
            # Display each requirement on a new line
            error_message = "Password must meet the following criteria:\n" \
                             "- Be at least 7 characters long\n" \
                             "- Contain at least 1 upper case character\n" \
                             "- Contain at least 1 symbol"
            label3.config(text=error_message)
    else:
        label3.config(text="Passwords do not match")

# Function to check the master password
def get_master_password():
    check_hashed_password = hashlib.sha256(txtBox.get().encode("utf-8")).hexdigest()
    cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [check_hashed_password])
    return cursor.fetchall()

# Function to check the password entered by the user
def check_password():
    match = get_master_password()
    if match:
        password_vault()
    else:
        txtBox.delete(0, "end")
        label5.config(text="Wrong Password")

# Function for the initial setup
def initial_use():
    global txtBox, txtBox1, label3, canvas, strength_var
    window.geometry("600x300")  

    label = Label(window, text="Create Master Password", anchor=CENTER)
    label.pack()

    txtBox = Entry(window, width=30, show="*")
    txtBox.pack()
    txtBox.focus()

    label2 = Label(window, text="Re-enter Password")
    label2.pack()

    txtBox1 = Entry(window, width=30, show="*")
    txtBox1.pack()

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

    # Bind the update_strength function to the password entry & repeat entry
    txtBox.bind('<KeyRelease>', lambda event, progress=progress: update_strength(canvas, strength_var, txtBox.get(), progress))
    txtBox1.bind('<KeyRelease>', lambda event, progress=progress: update_strength(canvas, strength_var, txtBox1.get(), progress))



    button = Button(window, text="Save", command=save_password)
    button.pack()

# Function for the login screen
def login_screen():
    global txtBox, label5
    window.geometry("600x200")
    
    label4 = Label(window, text="Enter your master password", anchor=CENTER)
    label4.pack()

    txtBox = Entry(window, width=30, show="*")
    txtBox.pack()
    txtBox.focus()

    label5 = Label(window)
    label5.pack()

    button = Button(window, text="Confirm", command=check_password)
    button.pack()

# Function for the password vault
def password_vault():
    for widget in window.winfo_children():
        widget.destroy()

    def add_entry():
        website = popUp("Add Entry", "Enter Website")
        username = popUp("Add Entry", "Enter User Name")
        password = popUp("Add Entry", "Enter Password")

        if website is not None and username is not None and password is not None:
            insert_fields = """INSERT INTO passwordvault(website, username, password)
                            VALUES(?, ?, ?)"""

            cursor.execute(insert_fields, (website, username, password))
            db.commit()

            password_vault()

    def remove_entry_confirmation(input):
        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete this entry?")
        if confirm:
            remove_entry(input)

    def remove_entry(input):
        cursor.execute("DELETE FROM passwordvault WHERE id = ?", (input,))
        db.commit()
        password_vault()

    def edit_entry(input):
        # Fetch the existing entry
        cursor.execute("SELECT * FROM passwordvault WHERE id = ?", (input,))
        entry = cursor.fetchone()

        # Ask user for updated data
        updated_website = popUp("Edit Entry", "Enter new website:", entry[1])
        updated_username = popUp("Edit Entry", "Enter new user name:", entry[2])
        updated_password = popUp("Edit Entry", "Enter new password:", entry[3])

        # Update the entry in the database
        cursor.execute("UPDATE passwordvault SET website=?, username=?, password=? WHERE id=?", (updated_website, updated_username, updated_password, input))
        db.commit()

        password_vault()

    window.geometry("800x600")

    btn = Button(window, text="Add Account", command=add_entry)
    btn.grid(row=1, column=0, pady=10, padx=(10, 0))

    label7 = Label(window, text="Password Vault", anchor=CENTER, font=('Arial', 16))
    label7.grid(row=0, column=0, columnspan=7, pady=10)

    # Headings for each column
    Label(window, text="Website", font=('Arial', 12, "bold")).grid(row=2, column=0, pady=5, padx=45)
    Label(window, text="User Name", font=('Arial', 12, "bold")).grid(row=2, column=1, pady=5, padx=45)
    Label(window, text="Password", font=('Arial', 12, "bold")).grid(row=2, column=2, pady=5, padx=45)
    Label(window, text="Password Strength", font=('Arial', 12, "bold")).grid(row=2, column=3, pady=5, padx=45)
    Label(window, text="Progress", font=('Arial', 12, "bold")).grid(row=2, column=4, pady=5, padx=45)
    Label(window, text="Actions", font=('Arial', 12, "bold")).grid(row=2, column=5, pady=5, padx=45)

    # Display entries in columns
    cursor.execute("SELECT * FROM passwordvault")
    array = cursor.fetchall()

    if array:
        for row_index, row in enumerate(array):
            Label(window, text=row[1], font=('Arial', 12, "bold")).grid(row=row_index + 3, column=0, pady=10, padx=45)
            Label(window, text=row[2], font=('Arial', 12, "bold")).grid(row=row_index + 3, column=1, pady=10, padx=45)
            password_label = Label(window, text=row[3], font=('Arial', 12, "bold"))
            password_label.grid(row=row_index + 3, column=2, pady=10, padx=45)

            # Display password strength for each password
            strength_var = StringVar()
            strength_var.set("Password Strength: " + check_password_strength(row[3]))
            Label(window, textvariable=strength_var, font=('Arial', 12, "bold")).grid(row=row_index + 3, column=3, pady=10, padx=45)

            # Create a new canvas for each entry
            progress_canvas = Canvas(window, width=70, height=10)
            progress_canvas.grid(row=row_index + 3, column=4, pady=5, padx=5)

            # Create a custom progress bar using a rectangle on the canvas
            progress = {"value": 0, "bar": progress_canvas.create_rectangle(0, 0, 0, 10, fill="green")}

            password_strength = check_password_strength(row[3])

            if password_strength == "Weak":
                progress_color = "red"
                progress_length = 30
            elif password_strength == "Medium":
                progress_color = "orange"
                progress_length = 70
            else:
                progress_color = "green"
                progress_length = 200

            progress_canvas.itemconfig(progress["bar"], fill=progress_color)
            progress_canvas.coords(progress["bar"], 0, 0, progress_length, 10)

            # Add Delete button for each entry with confirmation
            btn_delete = Button(window, text="Delete", command=lambda r=row[0]: remove_entry_confirmation(r))
            btn_delete.grid(row=row_index + 3, column=5, pady=10, padx=5)

            # Add Edit button for each entry
            btn_edit = Button(window, text="Edit", command=lambda r=row[0]: edit_entry(r))
            btn_edit.grid(row=row_index + 3, column=6, pady=10, padx=5)

# Initialise the application
check = cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    initial_use()

# Start the main loop
window.mainloop()
