import socket
import hmac
import hashlib
import time
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Konfigurasi server
HOST = '127.0.0.1'
PORT = 5000
KEY = b'supersecretkeysupersecretkey12'  # 32 bytes key

# Fungsi MAC
def generate_mac(data, algo):
    if algo == "HMAC-SHA256":
        return hmac.new(KEY, data, hashlib.sha256).digest()
    elif algo == "RIPEMD-256":
        h = hashlib.new('ripemd160')  # RIPEMD-256 tidak tersedia di hashlib, pakai ripemd160 sebagai simulasi
        h.update(data)
        return h.digest()
    elif algo == "AES-256-CMAC":
        cobj = CMAC.new(KEY, ciphermod=AES)
        cobj.update(data)
        return cobj.digest()
    else:
        raise ValueError("Algoritma tidak dikenali")

# Server socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print("Server is listening...")
    conn, addr = server_socket.accept()

    with conn:
        print(f"Connected by {addr}")

        # Terima algoritma
        algo_bytes = conn.recv(20)
        algorithm = algo_bytes.decode().strip()
        print(f"Algorithm selected: {algorithm}")

        while True:
            header = conn.recv(20)
            if not header:
                break
            data_len = int(header.decode().strip())

            data = b""
            while len(data) < data_len:
                packet = conn.recv(data_len - len(data))
                if not packet:
                    break
                data += packet

            mac = conn.recv(64)

            start = time.time()
            expected_mac = generate_mac(data, algorithm)
            end = time.time()
            comp_delay = (end - start) * 1000

            valid = hmac.compare_digest(mac, expected_mac)
            print(f"MAC {'valid' if valid else 'invalid'} | Computation Delay: {comp_delay:.3f} ms")
