from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from tink import aead
import os
import base64


KEY = os.urandom(32)  # Générer une clé de 32 octets (256 bits) pour AES

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length'))
        # print(length)
        body = self.rfile.read(length).decode('utf-8')
        # print(body)
        data = parse_qs(body)
        hashed_password = data['hashed_password'][0]
        print(hashed_password)
        hashed_password_bytes = hashed_password.encode('utf-8')  # Si hashed_password est une chaîne normale
        # ou hashed_password_bytes = bytes.fromhex(hashed_password) si c'est une chaîne hexadécimale
        encrypted_password = self.encrypt_aes(hashed_password_bytes)

        base64_encrypted_password = base64.b64encode(encrypted_password)
        print(base64_encrypted_password)
        
        self.send_response(200)
        #self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(base64_encrypted_password)

    def encrypt_aes(self, data):
        aead_primitive = aead.aead_from_url('tink://aead/aes-256-gcm')
        ciphertext = aead_primitive.encrypt(data, KEY, b'')
        return ciphertext
    
def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Server running on port {port}')
    httpd.serve_forever()

run()