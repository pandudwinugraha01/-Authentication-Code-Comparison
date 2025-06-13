import socket
import hmac
import hashlib
import time
from Crypto.Hash import RIPEMD160
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Konfigurasi server
HOST = '127.0.0.1'
PORT = 5000
KEY = b'0123456789ABCDEF0123456789ABCDEF'  # 32 bytes key

# Fungsi generate MAC sesuai algoritma
def generate_mac(data, algo):
    if algo == "HMAC-SHA256":
        return hmac.new(KEY, data, hashlib.sha256).digest()
    elif algo == "RIPEMD-160":
        h = RIPEMD160.new()
        h.update(data)
        return h.digest()
    elif algo == "AES-CMAC":
        cobj = CMAC.new(KEY, ciphermod=AES)
        cobj.update(data)
        return cobj.digest()
    else:
        raise ValueError("Algoritma tidak dikenali")

# Fungsi pilih mode output
def select_mode():
    print("Pilih mode output:")
    print("1. Tampilkan seluruh message (verbose)")
    print("2. Hanya tampilkan hasil ringkasan (summary)")
    while True:
        try:
            choice = int(input("Masukkan pilihan: "))
            if choice in (1, 2):
                return choice
            else:
                print("Pilihan tidak valid.")
        except ValueError:
            print("Input harus berupa angka.")

# Mulai server
mode = select_mode()

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print("\nServer is listening...")
        conn, addr = server_socket.accept()

        with conn:
            print(f"Connected by {addr}")

            # Terima algoritma
            algo_len_bytes = conn.recv(1)
            algo_len = int.from_bytes(algo_len_bytes, 'big')
            algo_bytes = conn.recv(algo_len)
            algorithm = algo_bytes.decode().strip()
            print(f"Algorithm selected: {algorithm}")

            total_samples = 0
            valid_count = 0
            invalid_count = 0
            total_comp_time = 0

            while True:
                header = conn.recv(4)
                if not header:
                    break

                data_len = int.from_bytes(header, 'big')
                data = b""
                while len(data) < data_len:
                    packet = conn.recv(data_len - len(data))
                    if not packet:
                        break
                    data += packet

                mac = conn.recv(32)

                start = time.time()
                expected_mac = generate_mac(data, algorithm)
                end = time.time()
                comp_delay = (end - start) * 1000  # ms

                valid = hmac.compare_digest(mac, expected_mac)
                total_samples += 1
                total_comp_time += comp_delay

                if valid:
                    valid_count += 1
                else:
                    invalid_count += 1

                if mode == 1:
                    print(f"Sample {total_samples} | MAC {'VALID' if valid else 'INVALID'} | Computation Delay: {comp_delay:.3f} ms")

            # Kesimpulan setelah koneksi client selesai
            print("\n--- SUMMARY ---")
            print(f"Total sample received: {total_samples}")
            print(f"Valid MAC: {valid_count}")
            print(f"Invalid MAC: {invalid_count}")
            if total_samples > 0:
                avg_comp_time = total_comp_time / total_samples
                print(f"Average computation delay: {avg_comp_time:.3f} ms")
            print("--- END ---\n")
            
        # Server kembali listening ke client baru
