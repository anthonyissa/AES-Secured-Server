from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from tink import aead, KeysetHandle
import tink
import os
import base64

def init_tink():
    try:
        aead.register()
    except tink.TinkError as e:
        print("Error initializing Tink: ", e)

init_tink()  # Initialize Tink

# Create an AES256 GCM key template and generate a keyset handle
key_template = aead.aead_key_templates.AES256_GCM
keyset_handle = KeysetHandle.generate_new(key_template)

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length'))
        body = self.rfile.read(length).decode('utf-8')
        data = parse_qs(body)
        hashed_password = data['hashed_password'][0]
        hashed_password_bytes = hashed_password.encode('utf-8')
        encrypted_password = self.encrypt_aes(hashed_password_bytes)
        base64_encrypted_password = base64.b64encode(encrypted_password)
        print(f"Encrypted password: {base64_encrypted_password}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(base64_encrypted_password)

    def encrypt_aes(self, data):
        # Get the primitive
        aead_primitive = keyset_handle.primitive(aead.Aead)
        # Encrypt data
        ciphertext = aead_primitive.encrypt(data, b'')  # Associated data is empty
        return ciphertext

    
def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Server running on port {port}')
    httpd.serve_forever()

run()