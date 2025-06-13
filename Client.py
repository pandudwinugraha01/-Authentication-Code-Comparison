import socket
import time
import hmac
import hashlib
import os
from Crypto.Hash import RIPEMD160
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Konfigurasi
HOST = '127.0.0.1'
PORT = 5000
KEY = b'0123456789ABCDEF0123456789ABCDEF'  # 32 bytes AES key

algorithms_list = ['HMAC-SHA256', 'RIPEMD-160', 'AES-CMAC']
plaintext_size = 1024 * 10  # 10 KB

# Fungsi generate MAC
def compute_mac(data, algo):
    if algo == 'HMAC-SHA256':
        return hmac.new(KEY, data, hashlib.sha256).digest()
    elif algo == 'RIPEMD-160':
        h = RIPEMD160.new()
        h.update(data)
        return h.digest()
    elif algo == 'AES-CMAC':
        c = CMAC.new(KEY, ciphermod=AES)
        c.update(data)
        return c.digest()
    else:
        raise ValueError(f"Unknown algorithm: {algo}")

# Fungsi pilih algoritma
def select_algorithm():
    print("Pilih algoritma:")
    for idx, algo in enumerate(algorithms_list, 1):
        print(f"{idx}. {algo}")
    
    while True:
        try:
            choice = int(input("Masukkan nomor pilihan: "))
            if 1 <= choice <= len(algorithms_list):
                return algorithms_list[choice - 1]
            else:
                print("Pilihan tidak valid.")
        except ValueError:
            print("Input harus angka.")

# Fungsi input jumlah sample
def get_sample_count():
    while True:
        try:
            count = int(input("Masukkan jumlah sample yang ingin dikirim: "))
            if count > 0:
                return count
            else:
                print("Jumlah sample harus lebih dari 0.")
        except ValueError:
            print("Input harus berupa angka.")

# Fungsi utama loop client
def main_loop():
    while True:
        selected_algo = select_algorithm()
        samples_per_algorithm = get_sample_count()

        print(f"\nMenjalankan pengujian dengan algoritma: {selected_algo}")
        print(f"Jumlah sample: {samples_per_algorithm}\n")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))

                # Kirim algoritma (kirim panjang + algoritma string)
                algo_bytes = selected_algo.encode()
                s.sendall(len(algo_bytes).to_bytes(1, 'big') + algo_bytes)

                for i in range(samples_per_algorithm):
                    msg = os.urandom(plaintext_size)

                    # Hitung MAC
                    start_comp = time.time()
                    mac = compute_mac(msg, selected_algo)
                    end_comp = time.time()
                    comp_delay = end_comp - start_comp

                    # Kirim data: panjang data + data + MAC
                    s.sendall(len(msg).to_bytes(4, 'big') + msg + mac)

                    print(f"Sample {i+1}/{samples_per_algorithm} | Comp Delay: {comp_delay:.6f}s")

            print("\nSesi pengujian selesai.\n")

        except Exception as e:
            print(f"Terjadi error: {e}\n")

        # Tanya apakah mau lanjut lagi
        ulang = input("Ingin melakukan pengujian lagi? (y/n): ").lower()
        if ulang != 'y':
            print("Program selesai.")
            break

# Eksekusi program
if __name__ == "__main__":
    main_loop()
