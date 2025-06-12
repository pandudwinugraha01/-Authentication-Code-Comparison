import socket
import hmac
import hashlib
import time
import random
import pandas as pd
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Konfigurasi client
HOST = '127.0.0.1'
PORT = 5000
KEY = b'supersecretkeysupersecretkey12'

# Fungsi MAC
def generate_mac(data, algo):
    if algo == "HMAC-SHA256":
        return hmac.new(KEY, data, hashlib.sha256).digest()
    elif algo == "RIPEMD-256":
        h = hashlib.new('ripemd160')
        h.update(data)
        return h.digest()
    elif algo == "AES-256-CMAC":
        cobj = CMAC.new(KEY, ciphermod=AES)
        cobj.update(data)
        return cobj.digest()
    else:
        raise ValueError("Algoritma tidak dikenali")

# Input pilihan algoritma
print("Pilih algoritma Authentication Code:")
print("1. HMAC-SHA256")
print("2. RIPEMD-256")
print("3. AES-256-CMAC")
pilihan = input("Masukkan pilihan (1/2/3): ")

if pilihan == '1':
    ALGORITHM = "HMAC-SHA256"
elif pilihan == '2':
    ALGORITHM = "RIPEMD-256"
elif pilihan == '3':
    ALGORITHM = "AES-256-CMAC"
else:
    print("Pilihan tidak valid!")
    exit()

# Ukuran data (Bytes)
data_sizes = [1024, 10*1024, 100*1024, 1024*1024]

# Simpan hasil pengujian
results = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))

    # Kirim pilihan algoritma ke server
    client_socket.sendall(ALGORITHM.ljust(20).encode())

    for size in data_sizes:
        print(f"\nTesting data size: {size} Bytes")

        total_comp_delay = 0
        total_comm_delay = 0

        for i in range(100):
            data = random.randbytes(size)

            # Computation delay
            start_comp = time.time()
            mac = generate_mac(data, ALGORITHM)
            end_comp = time.time()
            comp_delay = (end_comp - start_comp) * 1000
            total_comp_delay += comp_delay

            # Communication delay
            start_comm = time.time()
            header = str(len(data)).ljust(20).encode()
            client_socket.sendall(header)
            client_socket.sendall(data)
            client_socket.sendall(mac)
            end_comm = time.time()
            comm_delay = (end_comm - start_comm) * 1000
            total_comm_delay += comm_delay

            print(f"Sample {i+1}: Comp {comp_delay:.3f} ms | Comm {comm_delay:.3f} ms")

        avg_comp = total_comp_delay / 100
        avg_comm = total_comm_delay / 100

        results.append({
            "Algorithm": ALGORITHM,
            "Data Size (Bytes)": size,
            "Avg Computation Delay (ms)": avg_comp,
            "Avg Communication Delay (ms)": avg_comm
        })

# Simpan hasil ke CSV
df = pd.DataFrame(results)
df.to_csv(f"results_{ALGORITHM}.csv", index=False)
print("\nSemua hasil disimpan ke file CSV.")
