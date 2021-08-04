# Roei Gida, 322225897, Tomer Shay, 323082701
import base64
import socket
import sys
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password, salt):
    return Fernet(base64.urlsafe_b64encode(
        PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt.encode(), iterations=100000,
                   backend=default_backend()).derive(password.encode())))


if len(sys.argv) < 4:
    print("Not enough parameters")
    exit()

k = generate_key(sys.argv[1], sys.argv[2])
port = int(sys.argv[3])

receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_socket.bind(('0.0.0.0', port))  # listen to any IP
receiver_socket.listen(1000)

while True:
    client_sock, client_address = receiver_socket.accept()
    ciphertext = client_sock.recv(8192)
    plaintext = k.decrypt(ciphertext).decode("utf-8")

    current_time = time.strftime("%H:%M:%S", time.localtime(time.time()))
    print(plaintext, current_time)
    client_sock.close()
