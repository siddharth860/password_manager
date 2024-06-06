import tkinter
import random
import string
import secrets
import customtkinter
import keyring
import json
import sqlcipher3


current_user_key = None
current_username = None

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.geometry("1280x720")
app.title("Password Manager")

def show_frame(frame):
    frame.tkraise()

def create_connection(db_password):
    try:
        conn = sqlcipher3.connect('password_manager_encrypted.db')
        conn.execute(f"PRAGMA key='{db_password}'")
        return conn
    except sqlcipher3.DatabaseError as e:
        print(f"Error creating connection: {e}")
        return None


def create_tables():
    conn = create_connection('default-password')
    if conn is not None:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                     username TEXT PRIMARY KEY,
                     password TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                     username TEXT NOT NULL,
                     category TEXT NOT NULL,
                     service TEXT NOT NULL,
                     password TEXT NOT NULL,
                     FOREIGN KEY (username) REFERENCES users (username))''')
        conn.commit()
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

for frame in (signup_frame, login_frame, choice_frame,display_passwords_frame,add_password_frame):
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
    global current_user_key, current_user_id
    username = username_entry_signup.get()
    password = password_entry_signup.get()
    confirm_password = confirm_password_entry_signup.get()
    
    if password != confirm_password:
        signup_message.configure(text="Passwords do not match!", text_color="red")
        return

    passwords = retrieve_passwords(username)
    passwords['default'] = password
    store_passwords(username, passwords)
    
    conn = create_connection(password)  
    c = conn.cursor()
    
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        current_user_key = password  
        current_username = username  
        signup_message.configure(text="Signup successful!", text_color="green")
        show_frame(choice_frame)
    except sqlcipher3.IntegrityError:
        signup_message.configure(text="Username already exists!", text_color="red")
    
    conn.close()

    show_frame(login_frame)


sign_up_button = customtkinter.CTkButton(signup_frame, text="Sign Up", font=("Arial", 20), width=200, height=40, command=signup)
sign_up_button.grid(row=6, column=1, padx=20, pady=20)


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
    
    passwords = retrieve_passwords(username)
    current_user_key=passwords
    current_username=username
    if not passwords:
        login_message.configure(text="Username not found!", text_color="red")
    elif passwords.get('default') == password:
        show_passwords()
    else:
        login_message.configure(text="Incorrect password!", text_color="red")


login_button = customtkinter.CTkButton(login_frame, text="Login", font=("Arial", 20), width=200, height=40, command=login)
login_button.grid(row=6, column=1, padx=20, pady=20)

show_frame(choice_frame)
def show_passwords():
    global current_user_key, current_username
    for widget in display_passwords_frame.winfo_children():
        widget.destroy()

    title_label = customtkinter.CTkLabel(display_passwords_frame, text="Stored Passwords", font=("Arial", 30, 'bold'))
    title_label.grid(row=0, column=0, padx=20, pady=20)
    add_button=customtkinter.CTkButton(display_passwords_frame,text="Add",font=("Arial",20),width=200,height=40,command=lambda: show_frame(add_password_frame))
    add_button.grid(row=0, column=2,padx=20,pady=20)
 
    try:
        
        conn = create_connection(current_user_key)
        c = conn.cursor()
        c.execute("SELECT category, service, password FROM passwords WHERE username=?", (current_username,))
        passwords = c.fetchall()
        conn.close()

        if passwords:
            passwords_dict1 = {f"{category} - {service}": pwd for category, service, pwd in passwords}
            row_index = 1
            for key, value in passwords_dict1.items():
                password_label = customtkinter.CTkLabel(display_passwords_frame, text=f"{key}: {value}", font=("Arial", 20))
                password_label.grid(row=row_index, column=0, padx=20, pady=10)
                row_index += 1
        else:
            print("error")
    except Exception as e:
        print(f"Error retrieving passwords: {str(e)}")
    
    show_frame(display_passwords_frame)
def generator():
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation
    selection_list = letters + digits + special_chars
    password_len = 17
    password = ''
    for i in range(password_len):
        password+=''.join(secrets.choice(selection_list))
    addpassword_entry_signup.delete(0, tkinter.END)
    addpassword_entry_signup.insert(0,password)
service_entry_signup = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
service_entry_signup.grid(row=2, column=1, padx=20, pady=10, sticky='w')
service_label_signup = customtkinter.CTkLabel(add_password_frame, text="Service name", font=("Arial", 20))
service_label_signup.grid(row=2, column=0, padx=20, pady=10, sticky='e')

addpassword_entry_signup = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
addpassword_entry_signup.grid(row=3, column=1, padx=20, pady=10, sticky='w')
addpassword_label_signup = customtkinter.CTkLabel(add_password_frame, text="Password", font=("Arial", 20))
addpassword_label_signup.grid(row=3, column=0, padx=20, pady=10, sticky='e')
generator_button=customtkinter.CTkButton(add_password_frame,text="generate",font=("Arial",18),command=generator)
generator_button.grid(row=3,column=2,padx=20,pady=20)

category_entry_signup = customtkinter.CTkEntry(add_password_frame, width=300, height=35, font=("Arial", 18))
category_entry_signup.grid(row=4, column=1, padx=20, pady=10, sticky='w')
category_label_signup = customtkinter.CTkLabel(add_password_frame, text="Category", font=("Arial", 20))
category_label_signup.grid(row=4, column=0, padx=20, pady=10, sticky='e')
add_password_message = customtkinter.CTkLabel(add_password_frame, text="", font=("Arial", 20))
add_password_message.grid(row=5, column=1, padx=20, pady=10)
def add_password():
    global current_user_key, current_username
    
    category = category_entry_signup.get()
    service = service_entry_signup.get()
    password = addpassword_entry_signup.get()
    
    if not category or not service or not password:
        add_password_message.configure(text="All fields are required!", text_color="red")
        return
    
    
    conn = create_connection(current_user_key)
    c = conn.cursor()
    
    c.execute("INSERT INTO passwords (username, category, service, password) VALUES (?, ?, ?, ?)", 
              (current_username, category, service, password))
    conn.commit()
    conn.close()
    
    category_entry_signup.delete(0, tkinter.END)
    service_entry_signup.delete(0, tkinter.END)
    addpassword_entry_signup.delete(0, tkinter.END)
    add_password_message.configure(text="Password added successfully!", text_color="green")
add_button=customtkinter.CTkButton(add_password_frame,text="Add",font=("Arial",20),command=add_password)
add_button.grid(row=6,column=2,padx=20,pady=20)
app.mainloop()
