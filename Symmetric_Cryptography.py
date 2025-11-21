import time
import psutil
import math
import pandas as pd
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20, ARC4, ARC2, Salsa20
from Crypto.Random import get_random_bytes

# ---------------- Algorithm definitions ----------------
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

# ---------------- Utility functions ----------------
def pad(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    return data[:-data[-1]]

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {byte: data.count(byte) for byte in set(data)}
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

# ---------------- Benchmarking function ----------------
def measure_performance(name, data, iterations=3):
    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 ** 2)
    t0 = time.perf_counter()

    CipherClass, key_len = algorithms[name]
    key_bits = key_len * 8

    if name == "3DES":
        key = DES3.adjust_key_parity(get_random_bytes(key_len))
    else:
        key = get_random_bytes(key_len)

    # Determine block size
    block_size = CipherClass.block_size if name in block_ciphers else "N/A"

    # Encryption
    enc_start = time.time()
    for _ in range(iterations):
        if name in block_ciphers:
            cipher = CipherClass.new(key, CipherClass.MODE_ECB)
            encrypted = cipher.encrypt(pad(data, cipher.block_size))
        else:
            cipher = CipherClass.new(key=key)
            encrypted = cipher.encrypt(data)
    enc_end = time.time()

    # Decryption
    dec_start = time.time()
    for _ in range(iterations):
        if name in block_ciphers:
            cipher = CipherClass.new(key, CipherClass.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted))
        else:
            cipher = CipherClass.new(key=key)
            decrypted = cipher.decrypt(encrypted)
    dec_end = time.time()

    encryption_time = (enc_end - enc_start) / iterations
    decryption_time = (dec_end - dec_start) / iterations
    entropy = shannon_entropy(encrypted)

    mem_after = proc.memory_info().rss / (1024 ** 2)
    delta_mem = mem_after - mem_before

    return {
        "Algorithm": name,
        "Type": "Block" if name in block_ciphers else "Stream",
        "KeyBits": key_bits,
        "BlockSize": block_size,
        "Entropy": entropy,
        "ΔMem(MB)": delta_mem,
        "EncTime": encryption_time,
        "DecTime": decryption_time,
    }

# ---------------- Run benchmarks ----------------
def main():
    file_sizes = {
        "1KB": 1024,
        "1MB": 1024 * 1024,
        "100MB": 100 * 1024 * 1024,
    }

    results = []

    for size_label, size_bytes in file_sizes.items():
        print(f"\n--- Running for file size: {size_label} ---")
        data = get_random_bytes(size_bytes)
        for algo_name in algorithms.keys():
            r = measure_performance(algo_name, data)
            r["FileSize"] = size_label
            results.append(r)
            print(f"{algo_name:<10} {r['Type']:<6} BlockSize={r['BlockSize']:<6} Size={size_label:<6} Enc={r['EncTime']:.4f}s Dec={r['DecTime']:.4f}s Entropy={r['Entropy']:.4f} Mem={r['ΔMem(MB)']:.4f}MB")

    df = pd.DataFrame(results)
    df.to_csv("crypto_performance_results.csv", index=False)
    print("\n Results saved to 'crypto_performance_results.csv'")

    # ---------------- Plotting ----------------
    # 1️⃣ Block ciphers
    df_block = df[df["Type"] == "Block"]
    plt.figure(figsize=(10, 6))
    
    for algo in df_block["Algorithm"].unique():
        subset = df_block[df_block["Algorithm"] == algo]
        plt.plot(subset["FileSize"], subset["EncTime"], marker='o', label=f"{algo} Enc")
    plt.title("Block Cipher Encryption Time vs File Size")
    plt.xlabel("File Size")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid(True)
    plt.savefig("block_ciphers_enc.png", dpi=300)
    print(" Saved: block_ciphers_enc.png")

    # 2️⃣ Stream ciphers
    df_stream = df[df["Type"] == "Stream"]
    plt.figure(figsize=(10, 6))
    
    for algo in df_stream["Algorithm"].unique():
        subset = df_stream[df_stream["Algorithm"] == algo]
        plt.plot(subset["FileSize"], subset["EncTime"], marker='o', label=f"{algo} Enc")
    plt.title("Stream Cipher Encryption Time vs File Size")
    plt.xlabel("File Size")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid(True)
    plt.savefig("stream_ciphers_enc.png", dpi=300)
    print(" Saved: stream_ciphers_enc.png")

    # 3️⃣ Combined plot
    plt.figure(figsize=(10, 6))
    for algo in df["Algorithm"].unique():
        subset = df[df["Algorithm"] == algo]
        plt.plot(subset["FileSize"], subset["EncTime"], marker='o', label=f"{algo}")
    plt.title("All Ciphers Encryption Time vs File Size")
    plt.xlabel("File Size")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid(True)
    plt.savefig("all_ciphers_enc.png", dpi=300)
    print(" Saved: all_ciphers_enc.png")

    # 4️⃣ Plot Entropy
    plt.figure(figsize=(10, 6))
    for algo in df["Algorithm"].unique():
        subset = df[df["Algorithm"] == algo]
        plt.plot(subset["FileSize"], subset["Entropy"], marker='o', label=f"{algo}")
    plt.title("Entropy vs File Size for All Ciphers")
    plt.xlabel("File Size")
    plt.ylabel("Entropy")
    plt.legend()
    plt.grid(True)
    plt.savefig("entropy_all_ciphers.png", dpi=300)
    print(" Saved: entropy_all_ciphers.png")

    # 5️⃣ Plot Memory Usage (ΔMem)
    plt.figure(figsize=(10, 6))
    for algo in df["Algorithm"].unique():
        subset = df[df["Algorithm"] == algo]
        plt.plot(subset["FileSize"], subset["ΔMem(MB)"], marker='o', label=f"{algo}")
    plt.title("Memory Usage vs File Size for All Ciphers")
    plt.xlabel("File Size")
    plt.ylabel("Memory Usage (MB)")
    plt.legend()
    plt.grid(True)
    plt.savefig("memory_usage_all_ciphers.png", dpi=300)
    print(" Saved: memory_usage_all_ciphers.png")

if __name__ == "__main__":
    main()
