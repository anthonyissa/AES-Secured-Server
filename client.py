import tkinter as tk
from tkinter import messagebox
import requests
import bcrypt

def authenticate_user(username):
    with open("bdd.txt", "r", encoding='utf-8') as file:
        for line in file:
            user_info = line.strip().split(',')
            if user_info[0] == username:
                stored_salt = user_info[1]
                stored_encrypt_password = user_info[2]
                return True, stored_salt, stored_encrypt_password
        return False, None, None

def signup_user(username, password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Send hashed password
    response = requests.post("http://localhost:8000", data={'login': username, 'hashed_password': hashed_password})

    # Store user and salt in file
    with open("bdd.txt", "a", encoding='utf-8') as file:
        file.write(username + "," + salt.decode('utf-8') + "," + response.text + "\n")
    messagebox.showinfo("Succès", "Inscription réussie !")

def signin_user(username, password):
    login, stored_salt, stored_encrypt_password = authenticate_user(username)
    if login:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), stored_salt.encode('utf-8'))
        response = requests.post("http://localhost:8000", data={'login': username, 'hashed_password': hashed_password})
        encrypt_res = response.text
        if encrypt_res == stored_encrypt_password:
            show_welcome_screen(username)
        else:
            messagebox.showwarning("Erreur", "Mot de passe incorrect.")
    else:
        messagebox.showwarning("Erreur", "Utilisateur inconnu.")

def show_welcome_screen(username):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text=f"Bienvenue, {username}!").grid(row=0, padx=10, pady=10)
    tk.Button(root, text="Se déconnecter", command=show_login_screen).grid(row=1, padx=10, pady=10)

def show_login_screen():
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Username").grid(row=0, sticky="e", padx=10, pady=10)
    tk.Label(root, text="Password").grid(row=1, sticky="e", padx=10, pady=10)

    entry_username = tk.Entry(root)
    entry_password = tk.Entry(root, show="*")

    entry_username.grid(row=0, column=1, padx=10, pady=10)
    entry_password.grid(row=1, column=1, padx=10, pady=10)

    tk.Button(root, text='Sign Up', command=lambda: signup_user(entry_username.get(), entry_password.get())).grid(row=3, column=0, padx=10, pady=10)
    tk.Button(root, text='Sign In', command=lambda: signin_user(entry_username.get(), entry_password.get())).grid(row=3, column=1, padx=10, pady=10)

# Tkinter GUI
root = tk.Tk()
root.title("Authentification")

show_login_screen()

root.mainloop()