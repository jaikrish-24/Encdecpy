import tkinter as tk
from tkinter import messagebox, scrolledtext
import rsa
import base64

# Generate RSA keys
def generate_keys():
    public_key, private_key = rsa.newkeys(2048)
    return private_key, public_key

# Encrypt plaintext
def encrypt(plaintext, pub_key):
    try:
        encrypted_message = rsa.encrypt(plaintext.encode('utf-8'), pub_key)
        return base64.b64encode(encrypted_message).decode('utf-8')
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# Decrypt ciphertext
def decrypt(ciphertext, priv_key):
    try:
        decoded_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        decrypted_message = rsa.decrypt(decoded_ciphertext, priv_key)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Encrypt button event
def encrypt_message():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    if not plaintext:
        messagebox.showwarning("Input Error", "Please enter plaintext to encrypt.")
        return
    ciphertext = encrypt(plaintext, public_key)
    ciphertext_entry.delete("1.0", tk.END)
    ciphertext_entry.insert(tk.END, ciphertext)

# Decrypt button event
def decrypt_message():
    ciphertext = ciphertext_entry.get("1.0", tk.END).strip()
    if not ciphertext:
        messagebox.showwarning("Input Error", "Please enter ciphertext to decrypt.")
        return
    plaintext = decrypt(ciphertext, private_key)
    decrypted_text_entry.delete("1.0", tk.END)
    decrypted_text_entry.insert(tk.END, plaintext)

# Generate and display keys
def generate_and_display_keys():
    global private_key, public_key
    private_key, public_key = generate_keys()
    private_key_text.delete("1.0", tk.END)
    private_key_text.insert(tk.END, private_key.save_pkcs1().decode('utf-8'))
    public_key_text.delete("1.0", tk.END)
    public_key_text.insert(tk.END, public_key.save_pkcs1().decode('utf-8'))

# Create the main window
root = tk.Tk()
root.title("RSA Encryption/Decryption")

# Style configurations
font_style = ("Helvetica", 12)

# Create and place labels, entries, and buttons
tk.Label(root, text="Plaintext:", font=font_style).grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
plaintext_entry = scrolledtext.ScrolledText(root, width=60, height=5, font=font_style)
plaintext_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Ciphertext:", font=font_style).grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
ciphertext_entry = scrolledtext.ScrolledText(root, width=60, height=5, font=font_style)
ciphertext_entry.grid(row=1, column=1, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Encrypt", font=font_style, command=encrypt_message, bg="#4CAF50", fg="white")
encrypt_button.grid(row=2, column=0, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", font=font_style, command=decrypt_message, bg="#2196F3", fg="white")
decrypt_button.grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="Decrypted Text:", font=font_style).grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
decrypted_text_entry = scrolledtext.ScrolledText(root, width=60, height=5, font=font_style)
decrypted_text_entry.grid(row=3, column=1, padx=10, pady=10)

tk.Label(root, text="Private Key:", font=font_style).grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
private_key_text = scrolledtext.ScrolledText(root, width=60, height=5, font=font_style)
private_key_text.grid(row=4, column=1, padx=10, pady=10)

tk.Label(root, text="Public Key:", font=font_style).grid(row=5, column=0, padx=10, pady=10, sticky=tk.W)
public_key_text = scrolledtext.ScrolledText(root, width=60, height=5, font=font_style)
public_key_text.grid(row=5, column=1, padx=10, pady=10)

generate_keys_button = tk.Button(root, text="Generate Keys", font=font_style, command=generate_and_display_keys, bg="#FF9800", fg="white")
generate_keys_button.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Initialize the application by generating and displaying keys
generate_and_display_keys()

# Run the application
root.mainloop()
