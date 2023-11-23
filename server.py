from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import tink
from tink import aead
aead.register()
import os
import base64
import json
import bcrypt

keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
aead_primitive = keyset_handle.primitive(aead.Aead)

users = []

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        path = self.path
        if path == "/signup":
            self.handle_signup()
        elif path == "/signin":
            self.handle_signin()

    def handle_signup(self):
        length = int(self.headers.get('content-length'))
        body = self.rfile.read(length).decode('utf-8')
        data = parse_qs(body)
        username = data['username'][0]
        hashed_password = data['hashed_password'][0]
        salt = bcrypt.gensalt()
        hashed_salt_password = bcrypt.hashpw(hashed_password.encode('utf-8'), salt)
        crypted_password = encrypt_aes(hashed_salt_password)
        users.append((username, salt, crypted_password))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Signup successful')

    def handle_signin(self):
        length = int(self.headers.get('content-length'))
        body = self.rfile.read(length).decode('utf-8')
        data = parse_qs(body)
        username = data['username'][0]
        hashed_password = data['hashed_password'][0]
        user_exists, stored_salt, crypted_password = self.authenticate_user(username)
        if not user_exists:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'User not found')
            return
        stored_hashed_password = decrypt_aes(crypted_password)
        rehashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), stored_salt)
        if stored_hashed_password == rehashed_password:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Signin successful')
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Invalid password')

    def authenticate_user(self, username):
        for user in users:
            if user[0] == username:
                return True, user[1], user[2]
        return False, None, None

def encrypt_aes(data):
    ciphertext = aead_primitive.encrypt(data, b'')  # Associated data is empty
    return ciphertext
    
def decrypt_aes(data):
    plaintext = aead_primitive.decrypt(data, b'')
    return plaintext

def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Server running on port {port}')
    httpd.serve_forever()

run()
