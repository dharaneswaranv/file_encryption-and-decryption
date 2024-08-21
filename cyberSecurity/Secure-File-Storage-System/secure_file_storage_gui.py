import tkinter as tk
from tkinter import filedialog, messagebox
from encryption import encrypt_file, decrypt_file

def select_file():
    """Open file dialog to select a file."""
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def get_password():
    """Get password from entry widget."""
    return password_entry.get()

def encrypt():
    """Encrypt the selected file."""
    file_path = file_entry.get()
    password = get_password()
    if file_path and password:
        try:
            encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File '{file_path}' encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")

def decrypt():
    """Decrypt the selected file."""
    file_path = file_entry.get()
    password = get_password()
    if file_path and password:
        try:
            decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File '{file_path}' decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")

# Create main window
root = tk.Tk()
root.title("Secure File Storage System")

# File path entry
tk.Label(root, text="File:").grid(row=0, column=0, padx=10, pady=10)
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=10, pady=10)

# Browse button
browse_button = tk.Button(root, text="Browse", command=select_file)
browse_button.grid(row=0, column=2, padx=10, pady=10)

# Password entry
tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show='*', width=50)
password_entry.grid(row=1, column=1, padx=10, pady=10)

# Encrypt button
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=2, column=1, padx=10, pady=10)

# Decrypt button
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=2, column=2, padx=10, pady=10)

# Run the application
root.mainloop()
