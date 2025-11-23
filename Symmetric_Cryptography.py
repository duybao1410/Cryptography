import time
import psutil
import math
import pandas as pd
import matplotlib.pyplot as plt
from tabulate import tabulate
from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20, ARC4, ARC2, Salsa20
from Crypto.Random import get_random_bytes


# Algorithm definitions 
algorithms = {
    "AES-128": (AES, 16),
    "AES-192": (AES, 24),
    "AES-256": (AES, 32),
    "DES": (DES, 8),
    "3DES": (DES3, 24),
    "Blowfish": (Blowfish, 8),
    "RC2": (ARC2, 8),
    "RC4": (ARC4, 32),
    "ChaCha20": (ChaCha20, 32),
    "Salsa20": (Salsa20, 32),
}

block_ciphers = {"AES-128", "AES-192", "AES-256", "DES", "3DES", "Blowfish", "RC2"}


#Utility functions 
def pad(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    return data[:-data[-1]]

def shannon_entropy(data: bytes) -> float:
    freq = {byte: data.count(byte) for byte in set(data)}
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


#  Single measurement 
def measure_once(name, data, iterations=3):
    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 ** 2)

    CipherClass, key_len = algorithms[name]
    key_bits = key_len * 8

    if name == "3DES":
        key = DES3.adjust_key_parity(get_random_bytes(key_len))
    else:
        key = get_random_bytes(key_len)

    block_size = CipherClass.block_size if name in block_ciphers else None

    # Encryption time only 
    t0_enc = time.time()
    for _ in range(iterations):
        if name in block_ciphers:
            cipher = CipherClass.new(key, CipherClass.MODE_ECB)
            encrypted = cipher.encrypt(pad(data, cipher.block_size))
        else:
            cipher = CipherClass.new(key=key)
            encrypted = cipher.encrypt(data)
    enc_time = time.time() - t0_enc

    #Decryption time only 
    t0_dec = time.time()
    for _ in range(iterations):
        if name in block_ciphers:
            cipher = CipherClass.new(key, CipherClass.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted))
        else:
            cipher = CipherClass.new(key=key)
            decrypted = cipher.decrypt(encrypted)
    dec_time = time.time() - t0_dec

    # Entropy & Memory
    entropy = shannon_entropy(encrypted)
    mem_after = proc.memory_info().rss / (1024 ** 2)
    delta_mem = mem_after - mem_before

    return {
        "Enc(s)": enc_time,
        "Dec(s)": dec_time,
        "Enc/iter": enc_time / iterations,
        "Dec/iter": dec_time / iterations,
        "MemΔ(MB)": delta_mem,
        "Entropy": entropy,
        "KeyBits": key_bits,
        "BlockSize": block_size,
    }


# Average benchmark 
def benchmark_algorithm(name, data, repeat=5):
    runs = [measure_once(name, data) for _ in range(repeat)]

    return {
        "Algorithm": name,
        "Enc(s)": sum(r["Enc(s)"] for r in runs) / repeat,
        "Dec(s)": sum(r["Dec(s)"] for r in runs) / repeat,
        "Enc/iter": sum(r["Enc/iter"] for r in runs) / repeat,
        "Dec/iter": sum(r["Dec/iter"] for r in runs) / repeat,
        "MemΔ(MB)": sum(r["MemΔ(MB)"] for r in runs) / repeat,
        "Entropy": sum(r["Entropy"] for r in runs) / repeat,
        "KeyBits": runs[0]["KeyBits"],
        "BlockSize": runs[0]["BlockSize"],
        "Repeats": repeat,
    }


#  Main
def main():
    file_size_mb = 100
    file_bytes = file_size_mb * 1024 * 1024

    print(f"Generating {file_size_mb}MB random data...")
    data = get_random_bytes(file_bytes)

    print("Benchmarking...\n")

    results = []
    for algo in algorithms.keys():
        avg = benchmark_algorithm(algo, data)
        results.append(avg)

    df = pd.DataFrame(results)

    # -------- TABLE OUTPUT --------
    print("\n=== ENCRYPTION / DECRYPTION BENCHMARK (AVERAGED) ===\n")
    print(tabulate(df, headers="keys", tablefmt="psql", showindex=False, floatfmt=".6f"))

    df.to_csv("crypto_benchmark_enc_dec.csv", index=False)
    print("\nSaved: crypto_benchmark_enc_dec.csv")

    # -------- CHARTS --------
    plt.figure(figsize=(12, 6))
    plt.bar(df["Algorithm"], df["Enc(s)"])
    plt.title("Average Encryption Time (s)")
    plt.ylabel("Seconds")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("avg_encrypt_time.png", dpi=300)

    plt.figure(figsize=(12, 6))
    plt.bar(df["Algorithm"], df["Dec(s)"])
    plt.title("Average Decryption Time (s)")
    plt.ylabel("Seconds")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("avg_decrypt_time.png", dpi=300)

    print("Saved all charts.")


if __name__ == "__main__":
    main()
