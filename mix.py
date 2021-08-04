# Roei Gida, 322225897, Tomer Shay, 323082701
import random
import socket
import sys
import threading
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256


def decrypt_message(sk, message):
    secret_key = serialization.load_pem_private_key(sk, password=None, backend=default_backend())
    return secret_key.decrypt(message,
                              padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None))


def listen_and_merge(mix_socket, sk):
    global all_messages, mutex

    while True:
        client_sock, client_address = mix_socket.accept()
        ciphertext = client_sock.recv(8192)
        plaintext = decrypt_message(sk, ciphertext)

        temp = ""
        for byte in plaintext[0:4]:
            temp += str(int(byte)) + '.'
        dst_ip = temp[:-1]  # extracting the ip from the message
        plaintext = plaintext[4:]  # remove ip from the message

        dst_port = int.from_bytes(plaintext[:2], byteorder='big')  # extracting the port from the message
        plaintext = plaintext[2:]  # remove port from the message

        mutex.acquire()
        all_messages.append([dst_ip, dst_port, plaintext])  # insert the [ip, port, message] to the list
        mutex.release()

        client_sock.close()


if len(sys.argv) < 2:
    print("Not enough parameters")
    exit()

server_index = int(sys.argv[1])

ips_file = open("ips.txt", "r")
servers_info = ips_file.readlines()  # server information
ips_file.close()

current_server_info = servers_info[server_index - 1]
current_server_info.replace('\n', '')

listened_port = int(current_server_info.split(' ')[1])

sk_file = open("sk" + str(server_index) + ".pem", "rb")
sk = sk_file.read()  # secret key from skY.pem file
sk_file.close()

mix_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mix_socket.bind(('0.0.0.0', listened_port))  # listen to any IP
mix_socket.listen(1000)

all_messages = []

mutex = threading.Lock()
thread = threading.Thread(target=listen_and_merge, args=(mix_socket, sk,))
thread.start()

while True:
    time.sleep(60)  # wait till the next round

    mutex.acquire()
    random.shuffle(all_messages)  # randomly shuffles the messages list
    for message in all_messages:
        sender_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_sock.connect((message[0], message[1]))  # ip, port
        sender_sock.send(message[2])  # message
        sender_sock.close()
    all_messages = []  # clear the messages list
    mutex.release()
