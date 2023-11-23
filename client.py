import tkinter as tk
from tkinter import messagebox
import requests
import bcrypt

salt = bcrypt.gensalt()

def signup_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    response = requests.post("http://localhost:8000/signup", data={'username': username, 'hashed_password': hashed_password.decode('utf-8')})
    if response.status_code == 200:
        messagebox.showinfo("Success", "Signup successful")
    else:
        messagebox.showerror("Error", "Signup failed")

def signin_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    response = requests.post("http://localhost:8000/signin", data={'username': username, 'hashed_password': hashed_password.decode('utf-8')})
    if response.status_code == 200:
        show_welcome_screen(username)
    elif response.status_code == 401:
        messagebox.showwarning("Error", "Invalid password")
    elif response.status_code == 404:
        messagebox.showwarning("Error", "User not found")
    else:
        messagebox.showerror("Error", "Signin failed")

def show_welcome_screen(username):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text=f"Welcome, {username}!").grid(row=0, padx=10, pady=10)
    tk.Button(root, text="Sign Out", command=show_login_screen).grid(row=1, padx=10, pady=10)

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
root.title("Authentication")

show_login_screen()

root.mainloop()
