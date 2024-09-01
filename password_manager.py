import sqlite3
from cryptography.fernet import Fernet
import hashlib
import base64
import os

# Constants
DB_FILE = "password_manager.db"
KEY_FILE = "secret.key"

# Function to generate a base64-encoded key from the master password
def generate_key(master_password):
    # Hash the master password and encode it into base64
    key = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Function to encrypt a password
def encrypt_password(plain_password, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(plain_password.encode())

# Function to decrypt a password
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password).decode()

# Function to set up the database
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, service TEXT, username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

# Function to save the key to a file
def save_key(key):
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

# Function to load the encryption key from a file
def load_key():
    return open(KEY_FILE, 'rb').read()

# Function to add a password to the database
def add_password(service, username, plain_password, key):
    encrypted_password = encrypt_password(plain_password, key)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
              (service, username, encrypted_password))
    conn.commit()
    conn.close()
    print(f"Password for {service} added successfully.")

# Function to view all passwords
def view_passwords(key):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, service, username, password FROM passwords")
    rows = c.fetchall()
    conn.close()

    for row in rows:
        decrypted_password = decrypt_password(row[3], key)
        print(f"ID: {row[0]} | Service: {row[1]} | Username: {row[2]} | Password: {decrypted_password}")

# Function to delete a password
def delete_password(password_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE id=?", (password_id,))
    conn.commit()
    conn.close()
    print("Password deleted successfully.")

# Main menu function
def menu():
    print("\nPassword Manager")
    print("1. Add Password")
    print("2. View Passwords")
    print("3. Delete Password")
    print("4. Quit")

    choice = input("Enter choice: ")
    return choice

# Main function
def main():
    # Check if the database and key files exist
    if not os.path.exists(DB_FILE):
        setup_database()

    if not os.path.exists(KEY_FILE):
        master_password = input("Set a master password: ")
        key = generate_key(master_password)
        save_key(key)
        print("Master password set successfully.")
    else:
        master_password = input("Enter your master password: ")
        key = generate_key(master_password)
        saved_key = load_key()

        # Verify the key by directly comparing it with the saved key
        if saved_key != key:
            print("Incorrect master password!")
            return

    while True:
        choice = menu()

        if choice == "1":
            service = input("Enter the service name: ")
            username = input("Enter the username: ")
            plain_password = input("Enter the password: ")
            add_password(service, username, plain_password, key)

        elif choice == "2":
            view_passwords(key)

        elif choice == "3":
            password_id = int(input("Enter the ID of the password to delete: "))
            delete_password(password_id)

        elif choice == "4":
            print("Exiting Password Manager.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

