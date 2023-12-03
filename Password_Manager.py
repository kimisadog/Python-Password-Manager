from tkinter import *
from tkinter.ttk import Progressbar, Style, Treeview, Scrollbar, Button
import sqlite3
import hashlib
from tkinter import simpledialog
from tkinter import ttk, messagebox, StringVar, scrolledtext, Text
import webbrowser
import requests
import feedparser
from ttkthemes import ThemedStyle
from tkinterhtml import TkinterHtml
import requests
import pyperclip
import time
import threading
import ctypes

# Create the main window screen
window = Tk()
window.title("Password Manager")

# Apply the Arc theme
style = ThemedStyle(window)
style.set_theme("arc")

# Global variables
txtBox = None
canvas = None
strength_var = None
progress = None  

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


def popUp(title, text, initial_text=""):
    answer = simpledialog.askstring(title, text, initialvalue=initial_text)
    return answer

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

# Function to save password to the database
def save_password():
    global txtBox, txtBox1, label3, canvas  

    # Get the entered passwords
    password1 = txtBox.get()
    password2 = txtBox1.get()

    
    if password1 == password2:
        strength = check_password_strength(password1)
        if strength != "Weak":
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
                             "- Contain at least 1 symbol\n" \
                             "- Password must not be a commonly used word"
            label3.config(text=error_message)
    else:
        label3.config(text="Passwords do not match")



def get_master_password():
    check_hashed_password = hashlib.sha256(txtBox.get().encode("utf-8")).hexdigest()
    cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [check_hashed_password])
    return cursor.fetchall()

def check_password():
    match = get_master_password()
    if match:
        password_vault()
    else:
        txtBox.delete(0, "end")
        label5.config(text="Wrong Password")

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

   
    canvas = Canvas(window, width=200, height=20)
    canvas.pack()
    progress = {"value": 0, "bar": canvas.create_rectangle(0, 0, 0, 20, fill="green")}

    # Bind the update_strength function to the password entry & repeat entry
    txtBox.bind('<KeyRelease>', lambda event, progress=progress: update_strength(canvas, strength_var, txtBox.get(), progress))
    txtBox1.bind('<KeyRelease>', lambda event, progress=progress: update_strength(canvas, strength_var, txtBox1.get(), progress))

    button = Button(window, text="Save", command=save_password)
    button.pack()

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

def password_vault():
    for widget in window.winfo_children():
        widget.destroy()

    def add_entry():
        website = popUp("Add Entry", "Enter Website")
        username = popUp("Add Entry", "Enter User Name")
        password = popUp("Add Entry", "Enter Password")

        if website is not None and username is not None and password is not None:
            if is_password_common(password):
                messagebox.showwarning("Password Warning", "The entered password has been found in a breach. Please consider using a stronger password.")

            insert_fields = """INSERT INTO passwordvault(website, username, password) VALUES(?, ?, ?)"""
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

    cursor.execute("SELECT * FROM passwordvault")
    array = cursor.fetchall()

    if array:
        for row_index, row in enumerate(array):
            Label(password_tab, text=row[1], font=('Arial', 12, "bold")).grid(row=row_index + 3, column=0, pady=10, padx=45)
            Label(password_tab, text=row[2], font=('Arial', 12, "bold")).grid(row=row_index + 3, column=1, pady=10, padx=45)
            password_label = Label(password_tab, text=row[3], font=('Arial', 12, "bold"))
            password_label.grid(row=row_index + 3, column=2, pady=10, padx=45)

            strength_var = StringVar()
            strength_var.set("Password Strength: " + check_password_strength(row[3]))
            Label(password_tab, textvariable=strength_var, font=('Arial', 12, "bold")).grid(row=row_index + 3, column=3, pady=10, padx=45)

            progress_canvas = Canvas(password_tab, width=70, height=10)
            progress_canvas.grid(row=row_index + 3, column=4, pady=5, padx=5)

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
            btn_delete = Button(password_tab, text="Delete", command=lambda r=row[0]: remove_entry_confirmation(r))
            btn_delete.grid(row=row_index + 3, column=5, pady=10, padx=5)

            # Add Edit button for each entry
            btn_edit = Button(password_tab, text="Edit", command=lambda r=row[0]: edit_entry(r))
            btn_edit.grid(row=row_index + 3, column=6, pady=10, padx=5)

    # Second tab Section
    text_entry_tab = ttk.Frame(notebook)
    notebook.add(text_entry_tab, text="Check your Passwords")

    
    message_label = Label(text_entry_tab, text="Check if your password has been detected in a breach", font=("Arial", 14, "bold"))
    message_label.grid(row=0, column=0, columnspan=2, pady=(10, 5), padx=(10, 0))

    
    sub_heading_label = Label(text_entry_tab, text="This feature is powered by the 'Have I Been Pwned' free API", font=("Arial", 10))
    sub_heading_label.grid(row=1, column=0, columnspan=2, pady=(0, 10), padx=(10, 0))

    
    entry_text = Entry(text_entry_tab, width=30)
    entry_text.grid(row=2, column=0, pady=10, padx=(10, 0))

    
    status_label = Label(text_entry_tab, text="", foreground="red"
    status_label.grid(row=3, column=0, pady=5, padx=(10, 0), columnspan=2)

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
 

    # Insert the password tips into the Text widget
    #password_tips_text.insert("1.0", password_tips)

    # Useful links Section
    useful_links_box = Label(hints_tab, text="Placeholder: Useful Links", font=("Arial", 14, "bold"))
    useful_links_box.grid(row=0, column=3, pady=(10, 5), padx=(5, 10), sticky="ne")

    #Cyber New Section
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

# Check if a master password is already set
check = cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    initial_use()

window.mainloop()
