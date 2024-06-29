import random
import string
import secrets
import customtkinter
import keyring
import json
import sqlite3
import bcrypt
from tkinter import ttk

current_user_key = None
current_username = None


customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.geometry("1280x720")
app.title("Password Manager")

def show_frame(frame):
    frame.tkraise()
    if frame == display_passwords_frame:
        display_passwords()

def create_connection():
    try:
        conn = sqlite3.connect('password_manager.db')
        print("connection")
        return conn
    except sqlite3.DatabaseError as e:
        print(f"Error creating connection: {e}")
        return None
    except Exception as ex:
        print(f"Unexpected error creating connection: {ex}")
        return None

def create_tables():
    conn = create_connection()
    if conn is not None:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     username TEXT PRIMARY KEY,
                     password TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                     username TEXT NOT NULL,
                     category TEXT NOT NULL,
                     service TEXT NOT NULL,
                     service_username TEXT NOT NULL,
                     password TEXT NOT NULL,
                     FOREIGN KEY (username) REFERENCES users (username))''')
        conn.commit()
        print("table created successfully")
        conn.close()
    else:
        print("Error: Unable to create tables")
create_tables()

container = customtkinter.CTkFrame(app)
container.pack(fill="both", expand=True)

signup_frame = customtkinter.CTkFrame(container)
login_frame = customtkinter.CTkFrame(container)
choice_frame = customtkinter.CTkFrame(container)
display_passwords_frame=customtkinter.CTkFrame(container)
add_password_frame=customtkinter.CTkFrame(container)

for frame in (signup_frame, login_frame, choice_frame, display_passwords_frame, add_password_frame):
    frame.grid(row=0, column=0, sticky='nsew')

container.grid_rowconfigure(0, weight=1)
container.grid_columnconfigure(0, weight=1)

choice_frame.grid_rowconfigure(0, weight=1)
choice_frame.grid_rowconfigure(1, weight=1)
choice_frame.grid_rowconfigure(2, weight=0)
choice_frame.grid_rowconfigure(3, weight=1)
choice_frame.grid_columnconfigure(0, weight=1)

choice_title = customtkinter.CTkLabel(choice_frame, text="Password Manager", font=("Arial", 35, 'bold'))
choice_title.grid(row=0, column=0, padx=20, pady=20, sticky='n')

signup_button_choice = customtkinter.CTkButton(choice_frame, text="Sign Up", font=("Arial", 20), width=200, height=40, command=lambda: show_frame(signup_frame))
signup_button_choice.grid(row=1, column=0, padx=0, pady=0, sticky='n')

login_button_choice = customtkinter.CTkButton(choice_frame, text="Login", font=("Arial", 20), width=200, height=40, command=lambda: show_frame(login_frame))
login_button_choice.grid(row=2, column=0, padx=0, pady=0, sticky='n')

for i in range(7):
    signup_frame.grid_rowconfigure(i, weight=1)
signup_frame.grid_columnconfigure(0, weight=1)
signup_frame.grid_columnconfigure(2, weight=1)

signup_title = customtkinter.CTkLabel(signup_frame, text="Password Manager", font=("Arial", 35, 'bold'))
signup_title.grid(row=0, column=1, padx=20, pady=20)

sign_up_text = customtkinter.CTkLabel(signup_frame, text="Sign Up", font=("Arial", 30, 'bold'))
sign_up_text.grid(row=1, column=1, padx=20, pady=10)

username_entry_signup = customtkinter.CTkEntry(signup_frame, width=300, height=35, font=("Arial", 18))
username_entry_signup.grid(row=2, column=1, padx=20, pady=10, sticky='w')
username_label_signup = customtkinter.CTkLabel(signup_frame, text="Username", font=("Arial", 20))
username_label_signup.grid(row=2, column=0, padx=20, pady=10, sticky='e')

password_entry_signup = customtkinter.CTkEntry(signup_frame, width=300, height=35, font=("Arial", 18), show='*')
password_entry_signup.grid(row=3, column=1, padx=20, pady=10, sticky='w')
password_label_signup = customtkinter.CTkLabel(signup_frame, text="Password", font=("Arial", 20))
password_label_signup.grid(row=3, column=0, padx=20, pady=10, sticky='e')

confirm_password_entry_signup = customtkinter.CTkEntry(signup_frame, width=300, height=35, font=("Arial", 18), show='*')
confirm_password_entry_signup.grid(row=4, column=1, padx=20, pady=10, sticky='w')
confirm_password_label_signup = customtkinter.CTkLabel(signup_frame, text="Confirm Password", font=("Arial", 20))
confirm_password_label_signup.grid(row=4, column=0, padx=20, pady=10, sticky='e')

signup_message = customtkinter.CTkLabel(signup_frame, text="", font=("Arial", 20))
signup_message.grid(row=5, column=1, padx=20, pady=10)

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def store_passwords(username, passwords_dict):
    passwords_json = json.dumps(passwords_dict)
    keyring.set_password("PasswordManager", username, passwords_json)

def retrieve_passwords(username):
    passwords_json = keyring.get_password("PasswordManager", username)
    if passwords_json is None:
        return {}
    passwords_dict = json.loads(passwords_json)
    return passwords_dict

def signup():
    global current_user_key, current_username
    username = username_entry_signup.get()
    password = password_entry_signup.get()
    confirm_password = confirm_password_entry_signup.get()
    
    if password != confirm_password:
        signup_message.configure(text="Passwords do not match!", text_color="red")
        return

    hashed_password = hash_password(password)
    
    conn = create_connection()
    c = conn.cursor()
    
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        current_username = username
        signup_message.configure(text="Signup successful!", text_color="green")
        show_frame(choice_frame)
    except sqlite3.IntegrityError:
        signup_message.configure(text="Username already exists!", text_color="red")
    finally:
        conn.close()

signup_button = customtkinter.CTkButton(signup_frame, text="Sign Up", font=("Arial", 20), width=200, height=40, command=signup)
signup_button.grid(row=6, column=1, padx=20, pady=20)

for i in range(7):
    login_frame.grid_rowconfigure(i, weight=1)
login_frame.grid_columnconfigure(0, weight=1)
login_frame.grid_columnconfigure(2, weight=1)

login_title = customtkinter.CTkLabel(login_frame, text="Password Manager", font=("Arial", 35, 'bold'))
login_title.grid(row=0, column=1, padx=20, pady=20)

login_text = customtkinter.CTkLabel(login_frame, text="Login", font=("Arial", 30, 'bold'))
login_text.grid(row=1, column=1, padx=20, pady=10)

username_entry_login = customtkinter.CTkEntry(login_frame, width=300, height=35, font=("Arial", 18))
username_entry_login.grid(row=2, column=1, padx=20, pady=10, sticky='w')
username_label_login = customtkinter.CTkLabel(login_frame, text="Username", font=("Arial", 20))
username_label_login.grid(row=2, column=0, padx=20, pady=10, sticky='e')

password_entry_login = customtkinter.CTkEntry(login_frame, width=300, height=35, font=("Arial", 18), show='*')
password_entry_login.grid(row=3, column=1, padx=20, pady=10, sticky='w')
password_label_login = customtkinter.CTkLabel(login_frame, text="Password", font=("Arial", 20))
password_label_login.grid(row=3, column=0, padx=20, pady=10, sticky='e')

login_message = customtkinter.CTkLabel(login_frame, text="", font=("Arial", 20))
login_message.grid(row=5, column=1, padx=20, pady=10)

def login():
    global current_user_key, current_username
    username = username_entry_login.get()
    password = password_entry_login.get()
    
    conn = create_connection()
    c = conn.cursor()
    
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()
    
    if row is None:
        login_message.configure(text="Invalid username or password", text_color="red")
    else:
        stored_password = row[0]
        if verify_password(stored_password, password):
            current_username = username
            login_message.configure(text="Login successful!", text_color="green")
            show_frame(display_passwords_frame)
        else:
            login_message.configure(text="Invalid username or password", text_color="red")
    
    conn.close()

login_button = customtkinter.CTkButton(login_frame, text="Login", font=("Arial", 20), width=200, height=40, command=login)
login_button.grid(row=6, column=1, padx=20, pady=20)

display_passwords_frame.grid_rowconfigure(0, weight=1)
display_passwords_frame.grid_rowconfigure(1, weight=1)
display_passwords_frame.grid_rowconfigure(2, weight=1)
display_passwords_frame.grid_columnconfigure(0, weight=1)

display_passwords_title = customtkinter.CTkLabel(display_passwords_frame, text="Password Manager", font=("Arial", 35, 'bold'))
display_passwords_title.grid(row=0, column=0, padx=20, pady=20, sticky='n')

display_passwords_text = customtkinter.CTkLabel(display_passwords_frame, text="Your Passwords", font=("Arial", 30, 'bold'))
display_passwords_text.grid(row=1, column=0, padx=20, pady=10, sticky='n')
add_button=customtkinter.CTkButton(display_passwords_frame,text="Add",font=("Arial",20),width=200,height=40,command=lambda: show_frame(add_password_frame))
add_button.grid(row=0, column=2,padx=20,pady=20)

columns = ("Service", "Username", "Password")
password_tree = ttk.Treeview(display_passwords_frame, columns=columns, show="headings", height=30)
password_tree.heading("Service", text="Service")
password_tree.heading("Username", text="Username")
password_tree.heading("Password", text="Password")

password_tree.column("Service", width=300, anchor='center')
password_tree.column("Username", width=300, anchor='center')
password_tree.column("Password", width=300, anchor='center')

password_tree.grid(row=2, column=0, padx=20, pady=10, sticky='n')

scrollbar = ttk.Scrollbar(display_passwords_frame, orient="vertical", command=password_tree.yview)
password_tree.configure(yscrollcommand=scrollbar.set)

def display_passwords():
    for i in password_tree.get_children():
        password_tree.delete(i)
    passwords_dict = retrieve_passwords(current_username)
    for service, details in passwords_dict.items():
        password_tree.insert("", "end", values=(service, details['username'], details['password']))
def generator():
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation
    selection_list = letters + digits + special_chars
    password_len = 17
    password = ''
    for i in range(password_len):
        password+=''.join(secrets.choice(selection_list))
    password_entry.delete(0, tkinter.END)
    password_entry.insert(0,password)

add_password_frame.grid_rowconfigure(0, weight=1)
add_password_frame.grid_rowconfigure(1, weight=1)
add_password_frame.grid_rowconfigure(2, weight=1)
add_password_frame.grid_rowconfigure(3, weight=1)
add_password_frame.grid_rowconfigure(4, weight=1)
add_password_frame.grid_rowconfigure(5, weight=1)
add_password_frame.grid_rowconfigure(6, weight=1)
add_password_frame.grid_rowconfigure(7, weight=1)
add_password_frame.grid_columnconfigure(0, weight=1)
add_password_frame.grid_columnconfigure(2, weight=1)

add_password_title = customtkinter.CTkLabel(add_password_frame, text="Password Manager", font=("Arial", 35, 'bold'))
add_password_title.grid(row=0, column=1, padx=20, pady=20)

add_password_text = customtkinter.CTkLabel(add_password_frame, text="Add Password", font=("Arial", 30, 'bold'))
add_password_text.grid(row=1, column=1, padx=20, pady=10)

service_entry = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
service_entry.grid(row=2, column=1, padx=20, pady=10, sticky='w')
service_label = customtkinter.CTkLabel(add_password_frame, text="Service", font=("Arial", 20))
service_label.grid(row=2, column=0, padx=20, pady=10, sticky='e')

service_username_entry = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
service_username_entry.grid(row=3, column=1, padx=20, pady=10, sticky='w')
service_username_label = customtkinter.CTkLabel(add_password_frame, text="Service Username", font=("Arial", 20))
service_username_label.grid(row=3, column=0, padx=20, pady=10, sticky='e')

password_entry = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
password_entry.grid(row=4, column=1, padx=20, pady=10, sticky='w')
password_label = customtkinter.CTkLabel(add_password_frame, text="Password", font=("Arial", 20))
password_label.grid(row=4, column=0, padx=20, pady=10, sticky='e')
generator_button=customtkinter.CTkButton(add_password_frame,text="generate",font=("Arial",18),command=generator)
generator_button.grid(row=4,column=2,padx=20,pady=20)
category_entry = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
category_entry.grid(row=5, column=1, padx=20, pady=10, sticky='w')
category_label = customtkinter.CTkLabel(add_password_frame, text="Category", font=("Arial", 20))
category_label.grid(row=5, column=0, padx=20, pady=10, sticky='e')
back_button=customtkinter.CTkButton(add_password_frame,text="Back",font=("Arial",20),width=200,height=40,command=lambda: show_frame(display_passwords_frame))
back_button.grid(row=0, column=2,padx=20,pady=20)
add_password_message = customtkinter.CTkLabel(add_password_frame, text="", font=("Arial", 20))
add_password_message.grid(row=6, column=1, padx=20, pady=10)

def add_password():
    service = service_entry.get()
    service_username = service_username_entry.get()
    password = password_entry.get()
    category = category_entry.get()
    
    passwords_dict = retrieve_passwords(current_username)
    passwords_dict[service] = {
        'username': service_username,
        'password': password,
        'category': category
    }
    store_passwords(current_username, passwords_dict)
    
    add_password_message.configure(text="Password added successfully!", text_color="green")
    display_passwords()

add_password_button = customtkinter.CTkButton(add_password_frame, text="Add Password", font=("Arial", 20), width=200, height=40, command=add_password)
add_password_button.grid(row=7, column=1, padx=20, pady=20)

for i in range(6):
    display_passwords_frame.grid_rowconfigure(i, weight=1)
display_passwords_frame.grid_columnconfigure(0, weight=1)

show_frame(choice_frame)
app.mainloop()
