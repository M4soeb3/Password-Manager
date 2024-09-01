# Password-Manager
A simple password manager to securely store and manage passwords.

The password manager securely stores user credentials such as usernames and passwords for various services. It uses cryptography to ensure that all passwords are stored securely. A master password is set by the user upon first use, which generates a secure key stored on disk. This key is used to encrypt and decrypt the stored passwords. The application allows users to add, view, and delete passwords in a command-line interface environment.

Core Features
Secure password storage: Passwords are encrypted using a key derived from the master password.
Ease of use: A command-line interface guides the user through adding, retrieving, and deleting passwords.
Data integrity: All sensitive data is securely stored in an SQLite database, ensuring data persistence and integrity.

FUNCTION generate_key(master_password)
    key = SHA256_hash(master_password)
    return base64_encode(key)

FUNCTION encrypt_password(plain_password, key)
    cipher = Fernet(key)
    return cipher.encrypt(plain_password)

FUNCTION decrypt_password(encrypted_password, key)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_password)

FUNCTION setup_database()
    Connect to DB
    Create table if not exists (id, service, username, password)
    Close connection

FUNCTION save_key(key)
    Write key to file 'secret.key'

FUNCTION load_key()
    Read key from file 'secret.key'
    return key

FUNCTION add_password(service, username, plain_password, key)
    encrypted_password = encrypt_password(plain_password, key)
    Store encrypted_password in DB
    Print "Password added successfully."

FUNCTION view_passwords(key)
    Fetch all records from DB
    FOR each record in records
        Decrypt and display password

FUNCTION delete_password(password_id)
    Delete record from DB using password_id
    Print "Password deleted successfully."

FUNCTION menu()
    Display menu options
    Capture user choice
    return choice

FUNCTION main()
    IF database file and key file do not exist
        SETUP database
        Prompt user for a master password
        Generate and save key

    ELSE
        Prompt user for master password
        Generate key from input
        Load saved key
        IF loaded key != generated key
            Print "Incorrect master password!"
            EXIT

    WHILE true
        choice = menu()
        CASE choice OF
            "1": Prompt for service, username, password; Call add_password()
            "2": Call view_passwords()
            "3": Prompt for password_id; Call delete_password()
            "4": EXIT
            ELSE: Print "Invalid choice. Please try again."

IF '__name__' == '__main__'
    Call main()

Details in the Pseudocode
Key Management: The master password is hashed and base64 encoded to form a key that is consistently used across sessions, by comparing the saved key with the generated key upon login.
Functional Commands: The main menu drives the application, offering choices that invoke specific functionalities: adding, viewing, and deleting passwords, all secured through encryption.
Security Measures: The pseudocode emphasizes secure handling of passwords and robust checking of master password validity, ensuring that only authorized access is allowed.
