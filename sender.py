# Roei Gida, 322225897, Tomer Shay, 323082701
import base64
import socket
import sys
import time
from queue import PriorityQueue
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_message(pk, message):
    public_key = serialization.load_pem_public_key(pk, backend=default_backend())
    ciphertext = public_key.encrypt(message,
                                    padding=padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(),
                                                         label=None))
    return ciphertext


def generate_key(password, salt):
    return Fernet(base64.urlsafe_b64encode(
        PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt.encode(), iterations=100000,
                   backend=default_backend()).derive(password.encode())))


time.sleep(2)
if len(sys.argv) < 2:
    print("Not enough parameters")
    exit()

file_name = "messages" + sys.argv[1] + ".txt"
file = open(file_name, "r")
all_lines = file.readlines()
file.close()

all_messages = PriorityQueue()  # priority queue by rounds
for i in range(len(all_lines)):
    message = all_lines[i].split(' ')
    plaintext = message[0]
    k = generate_key(message[3], message[4])  # the symmetric key
    ciphertext = k.encrypt(plaintext.encode())

    ip = message[5].split('.')
    temp = b''
    for num in ip:  # ip to bytes
        temp += int(num).to_bytes(1, 'big')
    ip = temp

    port = int(message[6].replace('\n', ''))
    port = port.to_bytes(2, 'big')  # port to bytes

    full_message = ip + port + ciphertext  # chaining: IP || Port || message

    servers_order = message[1].split(',')
    servers_order.reverse()

    server_file = open("ips.txt", "r")
    server_file_lines = server_file.readlines()  # servers information
    server_file.close()

    curr_server_data = []
    for j in range(len(servers_order)):
        curr_server_index = int(servers_order[j])
        curr_server = server_file_lines[curr_server_index - 1]

        pk_file = open("pk" + str(curr_server_index) + ".pem", "rb")
        full_message = encrypt_message(pk_file.read(), full_message)  # encrypt the message
        pk_file.close()

        curr_server_data = curr_server.split(' ')
        curr_server_data[1].replace('\n', '')
        if j != len(servers_order) - 1:
            curr_server_port = int(curr_server_data[1]).to_bytes(2, 'big')

            curr_server_ip = curr_server_data[0].split('.')
            temp = b''
            for num in curr_server_ip:
                temp += int(num).to_bytes(1, 'big')
            curr_server_ip = temp

            full_message = curr_server_ip + curr_server_port + full_message  # chaining: IP || Port || message

    last_ip = curr_server_data[0]
    last_port = curr_server_data[1]

    all_messages.put((int(message[2]), [last_ip, last_port, full_message]))  # added the message into the priority queue

current_round = 0
while not all_messages.empty():  # send to server
    element = all_messages.get()
    next_round = element[0]
    if next_round > current_round:
        time.sleep(60 * (element[0] - current_round))  # wait 1-min per round
        current_round = next_round

    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sender_socket.connect((element[1][0], int(element[1][1])))
    sender_socket.send(element[1][2])
    sender_socket.close()
