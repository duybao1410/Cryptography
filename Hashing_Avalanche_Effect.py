import hashlib
import os

def hamming_distance(a: bytes, b: bytes) -> int:
    """Count differing bits between two equal-length byte strings"""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def avalanche_test_hash(hash_constructor, name: str, output_bytes: int, trials: int = 5000):
    print(f"\n=== {name} Avalanche Test ({trials:,} trials) ===")
    
    total_bits = output_bytes * 8
    flipped_bits_sum = 0

    for _ in range(trials):
        # Random message
        msg = os.urandom(128)
        
        # Flip the very first bit
        flipped_msg = bytearray(msg)
        flipped_msg[0] ^= 0b00000001
        
        # Correct way: pass data directly or use update()
        h1 = hash_constructor(msg).digest()           # Method 1 (preferred)
        h2 = hash_constructor(bytes(flipped_msg)).digest()
        
        flipped_bits_sum += hamming_distance(h1, h2)
    
    avg_flipped = flipped_bits_sum / trials
    percentage = (avg_flipped / total_bits) * 100
    
    print(f"Output size          : {total_bits} bits")
    print(f"Average flipped bits : {avg_flipped:.3f} / {total_bits}")
    print(f"Avalanche effect     : {percentage:.4f}%")
    print(f"Deviation from 50%   : {abs(percentage - 50):.4f}%")

def main():
    print("Cryptographic Hash Functions - Avalanche Effect Test")
    print("=" * 65)
    
    # MD5
    avalanche_test_hash(hashlib.md5,            "MD5",        16,  trials=10000)
    
    # SHA-2 family
    avalanche_test_hash(hashlib.sha224,         "SHA-224",    28,  trials=10000)
    avalanche_test_hash(hashlib.sha256,         "SHA-256",    32,  trials=10000)
    avalanche_test_hash(hashlib.sha384,         "SHA-384",    48,  trials=5000)
    avalanche_test_hash(hashlib.sha512,         "SHA-512",    64,  trials=5000)
    
    # SHA-3 family
    avalanche_test_hash(hashlib.sha3_224,       "SHA3-224",   28,  trials=10000)
    avalanche_test_hash(hashlib.sha3_256,       "SHA3-256",   32,  trials=10000)
    avalanche_test_hash(hashlib.sha3_384,       "SHA3-384",   48,  trials=5000)
    avalanche_test_hash(hashlib.sha3_512,       "SHA3-512",   64,  trials=5000)
    
    # SHAKE128 & SHAKE256 (variable output → we request 256 bytes)
    print("\n=== SHAKE128 & SHAKE256 (2048-bit output) ===")
    trials = 5000
    output_bytes = 256
    total_bits = output_bytes * 8
    
    for shake_func, name in [(hashlib.shake_128, "SHAKE128"), (hashlib.shake_256, "SHAKE256")]:
        flipped_sum = 0
        for _ in range(trials):
            msg = os.urandom(128)
            flipped = bytearray(msg)
            flipped[0] ^= 1
            h1 = shake_func(msg).read(output_bytes)
            h2 = shake_func(bytes(flipped)).read(output_bytes)
            flipped_sum += hamming_distance(h1, h2)
        avg = flipped_sum / trials
        perc = (avg / total_bits) * 100
        print(f"{name:9} → {perc:.4f}% (avg {avg:.2f} flipped bits)")

if __name__ == "__main__":
    main()