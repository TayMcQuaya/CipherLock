import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Function to derive key from password
def derive_key(password: str, salt: bytes = b'secure_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to encrypt a file
def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not file_path:
        return
    
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    key = derive_key(password)
    cipher = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()
    
    encrypted_data = cipher.encrypt(file_data)
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)

    messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_file_path}")

# Function to decrypt a file
def decrypt_file():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if not file_path or not file_path.endswith(".enc"):
        messagebox.showerror("Error", "Please select a valid encrypted file (.enc)!")
        return
    
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    key = derive_key(password)
    cipher = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        decrypted_data = cipher.decrypt(encrypted_data)
        
        original_file_path = file_path.replace(".enc", "")
        with open(original_file_path, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {original_file_path}")
    
    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted file!")

# Function to show instructions
def show_instructions():
    instructions = """
    How to Use:
    1. Select a file you want to encrypt.
    2. Enter a strong password.
    3. Click "Encrypt File" to create a secure version (.enc).
    4. To decrypt, select the encrypted file (.enc) and enter the same password.
    5. Click "Decrypt File" to restore the original file.
    """
    messagebox.showinfo("Instructions", instructions)

# GUI Setup
root = tk.Tk()
root.title("File Encryption Tool")
root.geometry("450x300")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
password_entry = tk.Entry(root, show="*", font=("Arial", 12), width=30)
password_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt File", font=("Arial", 12), command=encrypt_file)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", font=("Arial", 12), command=decrypt_file)
decrypt_button.pack(pady=10)

instructions_button = tk.Button(root, text="How to Use", font=("Arial", 12), command=show_instructions)
instructions_button.pack(pady=10)

root.mainloop()
