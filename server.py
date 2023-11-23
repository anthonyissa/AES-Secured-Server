from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import tink
from tink import aead
aead.register()
import os
import base64

keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
aead_primitive = keyset_handle.primitive(aead.Aead)

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length'))
        body = self.rfile.read(length).decode('utf-8')
        data = parse_qs(body)
        hashed_password = data['hashed_password'][0]
        print(f"Hashed password: {hashed_password}")
        hashed_password_bytes = hashed_password.encode('utf-8')
        print(f"Hashed password bytes: {hashed_password_bytes}")
        encrypted_password = self.encrypt_aes(hashed_password_bytes)
        base64_encrypted_password = base64.b64encode(encrypted_password)
        print(f"Encrypted password: {base64_encrypted_password}")
        decrypted_password = self.decrypt_aes(encrypted_password)
        print(f"Decrypted password: {decrypted_password}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(base64_encrypted_password)

    def encrypt_aes(self, data):
        ciphertext = aead_primitive.encrypt(data, b'')  # Associated data is empty
        return ciphertext
    
    def decrypt_aes(self, data):
        plaintext = aead_primitive.decrypt(data, b'')
        return plaintext

    
def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Server running on port {port}')
    httpd.serve_forever()

run()