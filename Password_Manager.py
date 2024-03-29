## Nathan Burke M2082128 - Final Year Project
## Python Password Manager

import ctypes
import hashlib
import pyodbc
import pyperclip
import requests
import sqlite3
import threading
import time
import webbrowser
from cryptography.fernet import Fernet
import feedparser
import bcrypt

# tkinter imports
from tkinter import  Tk, ttk,  Entry, Label, Button, Canvas, messagebox, simpledialog, StringVar, Text, filedialog, messagebox
from tkinter import *
from tkinter.ttk import Progressbar, Style, Treeview, Scrollbar
from ttkthemes import ThemedStyle
from tkinterhtml import TkinterHtml


# Function to generate a key for the vault
def generate_vault_key():
    key = Fernet.generate_key()
    filename = filedialog.asksaveasfilename(title="Save the Vault Key", filetypes=[("Key Files", "*.key")], defaultextension=".key")
    if filename:
        with open(filename, "wb") as key_file:
            key_file.write(key)
        messagebox.showinfo("Vault Key Generated", f"Vault key has been saved to {filename}\nPlease store it in a secure location.")

# Function to load the vault key
def load_vault_key():
    filename = filedialog.askopenfilename(title="Select Vault Key File", filetypes=[("Key Files", "*.key")])
    if filename:
        with open(filename, "rb") as key_file:
            return key_file.read()
    else:
        return None
    
def encrypt_vault_password(password):
    fernet = Fernet(vault_key)
    # Convert the password to bytes using UTF-8 encoding
    return fernet.encrypt(password.encode('utf-8'))

def decrypt_vault_password(encrypted_password):
    fernet = Fernet(vault_key)
    # Decrypt and convert back to string using UTF-8
    return fernet.decrypt(encrypted_password).decode('utf-8')

# Function to load a key for the DB
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password).decode()

key = load_key()

with open("encrypted_password.txt", "rb") as encrypted_file:
    encrypted_password = encrypted_file.read()

decrypted_password = decrypt_password(encrypted_password, key)

#print(decrypted_password) prints the password in plain text !!!major issue!!!

# Create the main window screen
window = Tk()
window.title("Password Manager")

# Apply the Arc theme
style = ThemedStyle(window)
style.set_theme("arc")

# Global variables
txtBox = None
txtBox_username = None
canvas = None
strength_var = None
progress = None  
label5 = None

# Azure SQL Database connection parameters
server = 'final-year-project2.database.windows.net'
database = 'Password Manager'
username = 'Password'
password = decrypted_password 
driver= '{ODBC Driver 17 for SQL Server}'

# Establish a connection to the Azure SQL database & making tables
with pyodbc.connect('DRIVER='+driver+';SERVER='+server+';PORT=1433;DATABASE='+database+';UID='+username+';PWD='+ password) as db:
    cursor = db.cursor()

    # Check and create 'users' table if it does not exist
    cursor.execute("""
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'users' AND type = 'U')
    BEGIN
        CREATE TABLE users(
            id INT PRIMARY KEY IDENTITY(1,1),
            username NVARCHAR(255) UNIQUE NOT NULL,
            master_password NVARCHAR(60) NOT NULL
        );
    END
    """)

    # Check and create 'passwordvault' table if it does not exist
    cursor.execute("""
    IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'passwordvault' AND type = 'U')
    BEGIN
        CREATE TABLE passwordvault(
            id INT PRIMARY KEY IDENTITY(1,1),
            website NVARCHAR(255) NOT NULL,
            username NVARCHAR(255) NOT NULL,
            password VARBINARY(MAX) NOT NULL,
            user_id INT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    END
    """)

    db.commit()

# Check if the user already has a vault key
if messagebox.askyesno("Vault Key Check", "Do you already have a vault key file?"):
    vault_key = load_vault_key()
    if vault_key is None:
        messagebox.showerror("No Vault Key", "No vault key file selected. The application will now exit.")
        sys.exit()
else:
    generate_vault_key()
    vault_key = load_vault_key()

#popup box for add entry function
def popUp(title, text, initial_text=""):
    answer = simpledialog.askstring(title, text, initialvalue=initial_text)
    return answer

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def save_new_user(username, password1, password2):
    if password1 == password2:
        if check_password_strength(password1) != "Weak":
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
            try:
                # Insert the username and hashed password into the database
                cursor.execute("INSERT INTO users (username, master_password) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
                db.commit()
                messagebox.showinfo("Registration Successful", "User registered successfully.")
                switch_to_login()
            except pyodbc.IntegrityError:
                messagebox.showerror("Registration Failed", "Username already exists.")
        else:
            if is_password_common(password1):
                messagebox.showerror("Weak Password", "Password is part of a common dictionary")  
            else:
                messagebox.showerror("Weak Password", "Password is too weak. Please choose a stronger password.\n\n" 
                             "Password must meet the following criteria:\n" \
                             "- Be at least 7 characters long\n" \
                             "- Contain at least 1 upper case character\n" \
                             "- Contain at least 1 symbol\n" \
                             "- Password must not be a commonly used word")
    else:
        messagebox.showerror("Password Mismatch", "Passwords do not match.")
       
        
def clear_window():
    for widget in window.winfo_children():
        widget.destroy()

def switch_to_login():
    clear_window()
    login_screen()

def switch_to_register():
    clear_window()
    register_user()
    
def logout():
    global current_user_id
    current_user_id = None  # Clearing the current user session
    switch_to_login()  # Switch back to the login screen

def register_user():
    global txtBox, txtBox_username, strength_var, canvas, progress
    clear_window()
    
    Label(window, text="Register New User", font=("Arial", 14)).pack(pady=10)

    Label(window, text="Username").pack()
    txtBox_username = Entry(window, width=30)
    txtBox_username.pack()

    Label(window, text="Enter Password").pack()
    txtBox = Entry(window, width=30, show="*")
    txtBox.pack()

    Label(window, text="Re-enter Password").pack()
    txtBox1 = Entry(window, width=30, show="*")
    txtBox1.pack()
    
    # Password strength indicator
    strength_var = StringVar()
    strength_var.set("Password Strength: ")
    strength_label = Label(window, textvariable=strength_var)
    strength_label.pack()

    canvas = Canvas(window, width=200, height=20)
    canvas.pack()
    progress = {"value": 0, "bar": canvas.create_rectangle(0, 0, 0, 10, fill="green")}

 
    txtBox.bind('<KeyRelease>', lambda event: update_strength(canvas, strength_var, txtBox.get(), progress))

    Button(window, text="Register", command=lambda: save_new_user(txtBox_username.get(), txtBox.get(), txtBox1.get())).pack(pady=5)

    Label(window, text="Already have an account?").pack()
    Button(window, text="Login", command=switch_to_login).pack()
    
    
def login_screen():
    global txtBox, txtBox_username, label5
    clear_window()
    
    Label(window, text="Login", font=("Arial", 14)).pack(pady=10)

    Label(window, text="Username").pack()
    txtBox_username = Entry(window, width=30)
    txtBox_username.pack()

    Label(window, text="Enter your master password").pack()
    txtBox = Entry(window, width=30, show="*")
    txtBox.pack()

    Button(window, text="Confirm", command=check_password).pack(pady=20)

    Label(window, text="Don't have an account yet?").pack()
    Button(window, text="Register", command=switch_to_register).pack()
    
    label5 = Label(window)  
    label5.pack()
    
#def hash_password(password):
#    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def is_password_common(password):
    # Hash the password using SHA-1
    hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()

    # Use the HIBP API to check if the password has been pwned
    response = requests.get(f'https://api.pwnedpasswords.com/range/{hashed_password[:5]}')
    suffixes = [line.split(':')[0] for line in response.text.splitlines()]

    return hashed_password[5:] in suffixes

def check_password_strength(password):
    if is_password_common(password):
        return "Weak"  # Password is part of a common dictionary

    symbol_count = sum(1 for char in password if not char.isalnum())
    digit_count = sum(1 for char in password if char.isdigit())
    upper_count = sum(1 for char in password if char.isupper())

    if len(password) > 12:
        return "Strong"
    elif symbol_count >= 2 and digit_count >= 1 and upper_count >= 1:
        return "Strong"
    elif len(password) >= 7 and symbol_count >= 1 and (digit_count >= 1 or upper_count >= 1):
        return "Medium"
    else:
        return "Weak"
    
def update_strength(parent_frame, strength_var, password, progress):
    if strength_var is None:
        strength_var = StringVar()
        strength_var.set("Password Strength: ")
        strength_label = Label(parent_frame, textvariable=strength_var)
        strength_label.grid(row=2, column=4, pady=5, padx=5)

    if progress is None:
        progress = {"value": 0, "bar": parent_frame.create_rectangle(0, 0, 0, 10, fill="green")}

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

        
def check_passwords_on_login(passwords):
    breached_passwords = []
    for password in passwords:
        # Hash the password using SHA-1
        hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = hashed_password[:5]
        suffix = hashed_password[5:]
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if suffix in response.text:
            breached_passwords.append(password)

    if breached_passwords:
        breached_passwords_str = ', '.join(breached_passwords)  # Join passwords with a comma and a space
        messagebox.showwarning("Password Breach Alert", f"Some of your passwords are breached!\n\nBreached passwords: {breached_passwords_str}")



def get_master_password():
    check_hashed_password = hashlib.sha256(txtBox.get().encode("utf-8")).hexdigest()
    cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [check_hashed_password])
    return cursor.fetchall()

def check_password():
    global txtBox_username, label5
    username = txtBox_username.get()
    entered_password = txtBox.get()
    cursor.execute("SELECT id, master_password FROM users WHERE username = ?", (username,))
    user_record = cursor.fetchone()
    if user_record and bcrypt.checkpw(entered_password.encode('utf-8'), user_record[1].encode('utf-8')):
        global current_user_id
        current_user_id = user_record[0]
        password_vault()
        #check_passwords_on_login()
    else:
        txtBox.delete(0, "end")
        label5.config(text="Wrong Username or Password")


def password_vault():
    for widget in window.winfo_children():
        widget.destroy()
        
    
    def add_entry():
        website = popUp("Add Entry", "Enter Website")
        username = popUp("Add Entry", "Enter User Name")
        password = popUp("Add Entry", "Enter Password")

        if website is not None and username is not None and password is not None:
            encrypted_password = encrypt_vault_password(password)  # Encrypt the password
            insert_fields = """INSERT INTO passwordvault(website, username, password, user_id) VALUES(?, ?, ?, ?)"""
            cursor.execute(insert_fields, (website, username, encrypted_password, current_user_id))
            db.commit()
            password_vault()
        

    def remove_entry(input):
        cursor.execute("DELETE FROM passwordvault WHERE id = ?", (input,))
        db.commit()
        password_vault()
        
    def remove_entry_confirmation(input):
        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete this entry?")
        if confirm:
            remove_entry(input)

    def edit_entry(input):
        cursor.execute("SELECT * FROM passwordvault WHERE id = ?", (input,))
        entry = cursor.fetchone()

        updated_website = popUp("Edit Entry", "Enter new website:", entry[1])
        updated_username = popUp("Edit Entry", "Enter new user name:", entry[2])
        updated_password = popUp("Edit Entry", "Enter new password:", entry[3])
        encrypted_password = encrypt_vault_password(updated_password)  # Encrypt the new password

        cursor.execute("UPDATE passwordvault SET website=?, username=?, password=? WHERE id=?", (updated_website, updated_username, encrypted_password, input))
        db.commit()

        password_vault()

    window.geometry("800x600")

    # Create a notebook (tabs)
    notebook = ttk.Notebook(window)
    notebook.grid(row=0, column=0, columnspan=7, pady=10)

    # First tab - Password Vault
    password_tab = ttk.Frame(notebook)
    notebook.add(password_tab, text='Password Vault')

    btn = Button(password_tab, text="Add Account", command=add_entry)
    btn.grid(row=1, column=0, pady=10, padx=(10, 0))

    label7 = Label(password_tab, text="Password Vault", anchor='center', font=('Arial', 16))
    label7.grid(row=0, column=0, columnspan=7, pady=10)
    
 
    Label(password_tab, text="Website", font=('Arial', 12, "bold")).grid(row=2, column=0, pady=5, padx=45)
    Label(password_tab, text="User Name", font=('Arial', 12, "bold")).grid(row=2, column=1, pady=5, padx=45)
    Label(password_tab, text="Password", font=('Arial', 12, "bold")).grid(row=2, column=2, pady=5, padx=45)
    Label(password_tab, text="Password Strength", font=('Arial', 12, "bold")).grid(row=2, column=3, pady=5, padx=45)
    Label(password_tab, text="Progress", font=('Arial', 12, "bold")).grid(row=2, column=4, pady=5, padx=45)
    Label(password_tab, text="Actions", font=('Arial', 12, "bold")).grid(row=2, column=5, pady=5, padx=45)

    #only show logged in users passwords 
    cursor.execute("SELECT * FROM passwordvault WHERE user_id = ?", (current_user_id,))
    array = cursor.fetchall()

    decrypted_passwords = []
    if array:
        for row_index, row in enumerate(array):
            decrypted_password = decrypt_vault_password(row[3])
            decrypted_passwords.append(decrypted_password)

            # Use decrypted_password for further processing
            Label(password_tab, text=row[1], font=('Arial', 12, "bold")).grid(row=row_index + 3, column=0, pady=10, padx=45)
            Label(password_tab, text=row[2], font=('Arial', 12, "bold")).grid(row=row_index + 3, column=1, pady=10, padx=45)
            password_label = Label(password_tab, text=decrypted_password, font=('Arial', 12, "bold"))
            password_label.grid(row=row_index + 3, column=2, pady=10, padx=45)

            # Check password strength and if it is common
            strength_var = StringVar()
            strength = check_password_strength(decrypted_password)
            is_common = is_password_common(decrypted_password)
            strength_var.set(f"Password Strength: {strength} (Detected in breach?: {'Yes' if is_common else 'No'})")
            check_passwords_on_login([decrypted_password])  # Pass a list containing the decrypted password
            Label(password_tab, textvariable=strength_var, font=('Arial', 12, "bold")).grid(row=row_index + 3, column=3, pady=10, padx=45)

            progress_canvas = Canvas(password_tab, width=70, height=10)
            progress_canvas.grid(row=row_index + 3, column=4, pady=5, padx=5)

            progress = {"value": 0, "bar": progress_canvas.create_rectangle(0, 0, 0, 10, fill="green")}
            password_strength = strength

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
            btn_delete = Button(password_tab, text="Delete", command=lambda r=row[0]: remove_entry_confirmation(r))
            btn_delete.grid(row=row_index + 3, column=5, pady=10, padx=5)

            # Add Edit button for each entry
            btn_edit = Button(password_tab, text="Edit", command=lambda r=row[0]: edit_entry(r))
            btn_edit.grid(row=row_index + 3, column=6, pady=10, padx=5)
            

    logout_btn = Button(password_tab, text="Logout", command=logout)
    logout_btn.grid(row=1, column=6, pady=10, padx=10)  # Adjust position as needed



    # Second tab Section
    text_entry_tab = ttk.Frame(notebook)
    notebook.add(text_entry_tab, text="Check your Passwords")

    
    message_label = Label(text_entry_tab, text="Check if your password has been detected in a breach", font=("Arial", 14, "bold"))
    message_label.grid(row=0, column=0, columnspan=2, pady=(10, 5), padx=(10, 0))

    
    sub_heading_label = Label(text_entry_tab, text="This feature is powered by the 'Have I Been Pwned' free API", font=("Arial", 10))
    sub_heading_label.grid(row=1, column=0, columnspan=2, pady=(0, 10), padx=(10, 0))

    
    entry_text = Entry(text_entry_tab, width=30)
    entry_text.grid(row=2, column=0, pady=10, padx=(10, 0))

    
    status_label = Label(text_entry_tab, text="", foreground="red")
    status_label.grid(row=3, column=0, pady=5, padx=(10, 0), columnspan=2)

    #This section of the code uses HIBP API and is not entirely my own code 
    def check_and_display_text_entry_status():
        entered_text = entry_text.get()

        # Hash the entered text using SHA-1
        hashed_text = hashlib.sha1(entered_text.encode()).hexdigest().upper()

        # Take the first 5 characters of the hashed text (the prefix)
        prefix = hashed_text[:5]

        # Take the remaining characters of the hashed text (the suffix)
        suffix = hashed_text[5:]

        # Make a request to the HIBP API to check if the text has been breached
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')

        # Check if the suffix of the hashed text appears in the response
        if suffix in response.text:
            status_label.config(text=f"The entered password '{entered_text}' has been found in a breach. Please consider using a stronger password and changing any accounts that use this password.", foreground="red")
        else:
            status_label.config(text=f"The entered password '{entered_text}' is safe.", foreground="green")

    confirm_button = Button(text_entry_tab, text="Confirm", command=check_and_display_text_entry_status)
    confirm_button.grid(row=2, column=1, pady=10, padx=(10, 0))
    

    
    # Third tab section
    hints_tab = ttk.Frame(notebook)
    notebook.add(hints_tab, text='Useful Hints and Tips')
    #Security Tips section
    password_security_box = Label(hints_tab, text="Password Security Tips", font=("Arial", 14, "bold"))
    password_security_box.grid(row=0, column=0, pady=(10, 5), padx=(10, 5), sticky="nw")

  
    password_scrollbar = Scrollbar(hints_tab, orient=VERTICAL)
    password_scrollbar.grid(row=1, column=0, pady=(5, 10), padx=(575, 5), sticky="ns")
   
    password_tips_text = Text(hints_tab, wrap="word", width=70, height=30, yscrollcommand=password_scrollbar.set)
    password_tips_text.grid(row=1, column=0, pady=(5, 10), padx=(10, 5), sticky="sw")
   
    password_scrollbar.config(command=password_tips_text.yview)
    
    password_tips = (
        "1. Create Strong and Long Passwords:\n"
        "- Your passwords should be at least 12 characters long. Longer passwords provide better protection for your accounts.\n\n\n"

        "2. Use Memorable Passphrases:\n"
        "- Consider using passphrases - sequences of words or a mix of words and characters. Passphrases are easier to remember and can be more secure than simple passwords.\n\n\n"

        "3. Avoid Easy-to-Guess Choices:\n"
        "- Stay away from common passwords like 'password123' or easily guessable words. Opt for more complex combinations to make it harder for others to access your accounts.\n\n\n"

        "4. Add Extra Security with Multi-Factor Authentication (MFA):\n"
        "- Enable multi-factor authentication whenever possible. This adds an extra layer of security by requiring a second form of verification beyond your password.\n\n\n"

        "5. Change Your Passwords Regularly:\n"
        "- Update your passwords periodically. Changing them regularly helps protect your accounts, especially if there's a chance they could be compromised.\n\n\n"

        "6. Stay Informed About Security:\n"
        "- Learn about creating strong passwords and how to recognize phishing attempts. Being informed helps you better safeguard your accounts from potential threats.\n\n\n"

        "7. Trustworthy Password Handling:\n"
        "- Use platforms that securely store and handle your passwords. Avoid services that store passwords in plain text. Your passwords should always be treated with care."
    )
    
    
    # Insert the password tips into the Text widget with the first line in bold
    current_index = "1.0"
    for tip in password_tips.split("\n\n\n"):
        lines = tip.split("\n", 1)
        if len(lines) > 1:
            password_tips_text.insert(current_index, lines[0] + "\n", "bold")
            password_tips_text.insert(END, lines[1] + "\n")
            current_index = password_tips_text.index(END)

    
    password_tips_text.tag_configure("bold", font=("Arial", 12, "bold"))

    # Useful links Section
    useful_links_box = Label(hints_tab, text="Useful Links", font=("Arial", 14, "bold"))
    useful_links_box.grid(row=0, column=3, pady=(10, 5), padx=(5, 10), sticky="nw")

    useful_links_text = Text(hints_tab, wrap="word", width=70, height=30)
    useful_links_text.grid(row=1, column=3, pady=(5, 10), padx=(5, 10), sticky="nw")

    useful_links = (
        "1. StaySafeOnline - https://staysafeonline.org\n\n"
        "2. LastPass Blog - https://blog.lastpass.com\n\n"
        "3. How Secure Is My Password? - https://howsecureismypassword.net\n\n"
        "4. TwoFactorAuth.org - https://twofactorauth.org\n\n"
        "5. OWASP - https://owasp.org\n\n"
        "6. Cybrary - https://www.cybrary.it\n\n"
        "7. Self Surveillance - https://www.eff.org/pages/surveillance-self-defense\n\n"
        "8. MITRE ATT&CK - https://attack.mitre.org\n\n"
        "9. Krebs on Security - https://krebsonsecurity.com"
)

    useful_links_text.config(state="normal")
    for link in useful_links.split("\n"):
        if link.strip():
            lines = link.split(" - ", 1)
            if len(lines) > 1:
                useful_links_text.insert("end", lines[0].strip() + "\n", "bold")
                link_start = useful_links_text.index("end-2c")
                link_text = lines[1].strip()  # Use the entire remaining part as link text
                useful_links_text.insert("end", link_text + "\n\n", "hyperlink")
                link_end = useful_links_text.index('end-1c') + "+4c"
                useful_links_text.tag_add("hyperlink", link_start, link_end)

    useful_links_text.tag_configure("bold", font=("Arial", 12, "bold"))
    useful_links_text.tag_configure("hyperlink", foreground="blue", underline=True)
    useful_links_text.tag_bind("hyperlink", "<Button-1>", lambda e: open_link(useful_links_text.get(useful_links_text.index("current linestart"), useful_links_text.index("current lineend"))))

    useful_links_text.config(state="disabled")


    def open_link(url):
        webbrowser.open(url)

    #Cyber News Section
    rss_feed_label = Label(hints_tab, text="Cybersecurity News:", font=("Arial", 14, "bold"))
    rss_feed_label.grid(row=2, column=0, pady=(5, 0), padx=(10, 5), sticky="sw")

    rss_feed_text = Text(hints_tab, wrap="word", width=70, height=30)
    rss_feed_text.grid(row=3, column=0, pady=(0, 10), padx=(10, 5), columnspan=2, sticky="nw")

    
    def update_rss_feed():
        rss_url = "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"
        try:
            feed = feedparser.parse(rss_url)
            entries = feed.entries[:10]  

            for entry in entries:
                rss_feed_text.tag_configure("bold", font=("Arial", 12, "bold"))
                rss_feed_text.tag_configure("hyperlink", foreground="blue", underline=True)
                rss_feed_text.insert("end", f"{entry.title}\n", "bold")

                link_start = rss_feed_text.index("end-1c")  
                rss_feed_text.insert("end", f"{entry.link}\n\n", "hyperlink")
                link_end = rss_feed_text.index('end-1c')  

                rss_feed_text.tag_add("hyperlink", link_start, link_end)
                rss_feed_text.tag_bind("hyperlink", "<Button-1>", lambda e, link=entry.link: open_link(link))

            rss_feed_text.config(state="normal")  
        except Exception as e:
            rss_feed_text.delete(1.0, "end")
            rss_feed_text.insert("insert", f"Error fetching RSS feed: {str(e)}")

    
    def open_link(url):
        webbrowser.open(url)
        
    update_rss_feed()

    
    update_rss_button = Button(hints_tab, text="Update RSS Feed", command=update_rss_feed)
    update_rss_button.grid(row=3, column=1, pady=(0, 10), padx=(5, 10), sticky="se")
    


   #4th Tab Section
    password_generator_tab = ttk.Frame(notebook)
    notebook.add(password_generator_tab, text='Password Generator')

    
    length_label = Label(password_generator_tab, text="Enter Password Length:")
    length_label.grid(row=0, column=0, pady=(10, 5), padx=(10, 0), sticky="w")

    length_entry = Entry(password_generator_tab, width=5)
    length_entry.grid(row=0, column=1, pady=(10, 5), padx=(0, 10), sticky="w")

    
    def generate_password():
        password_length = length_entry.get()

        # Make a request to the password generator API
        api_url = f'https://api.api-ninjas.com/v1/passwordgenerator?length={password_length}'
        response = requests.get(api_url, headers={'X-Api-Key': 'bI7ka/glDE5e7NW3OdFmww==TRHqpqBzTURsvLKc'})

        if response.status_code == requests.codes.ok:
            generated_password = response.json().get('random_password', '')
            password_result.config(text=generated_password)
            copy_button.config(state="normal")
        else:
            password_result.config(text=f"Error: {response.status_code} {response.text}")

    def copy_to_clipboard():
        generated_password = password_result.cget("text")
        if generated_password:
            pyperclip.copy(generated_password)
            clear_clipboard_thread = threading.Timer(15, clear_clipboard_windows)
            clear_clipboard_thread.start()

    def clear_clipboard_windows():
       
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        ctypes.windll.user32.CloseClipboard()

    
    generate_button = Button(password_generator_tab, text="Generate Password", command=generate_password)
    generate_button.grid(row=1, column=0, pady=5, padx=(10, 0), sticky="w")

    
    password_result = Label(password_generator_tab, text="")
    password_result.grid(row=1, column=1, pady=5, padx=(0, 10), sticky="w")

    
    copy_button = Button(password_generator_tab, text="Copy to Clipboard", command=copy_to_clipboard, state="disabled")
    copy_button.grid(row=2, column=0, pady=5, padx=(10, 0), sticky="w", columnspan=2)


    window.update()
    
    #Set the window size to fit the content
    window.geometry("")
    
    #Update the window size after adding widgets
    window.update_idletasks()
    window.geometry(f"{window.winfo_reqwidth()}x{window.winfo_reqheight()}")


login_screen() # Start with login screen
window.mainloop()
