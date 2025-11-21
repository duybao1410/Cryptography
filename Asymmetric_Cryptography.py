import time
import os
import psutil
from tabulate import tabulate

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from phe import paillier

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


process = psutil.Process(os.getpid())


def mem_usage():
    return process.memory_info().rss


# =============================
# Benchmark helper function
# =============================
def benchmark(name, keygen_fn, sign_fn, verify_fn, get_sizes_fn):
    mem_before = mem_usage()

    # Key generation
    t0 = time.time()
    private_key, public_key = keygen_fn()
    keygen_t = time.time() - t0

    message = b"Benchmark asymmetric cryptography"
    signature = None

    # Sign
    if sign_fn:
        t0 = time.time()
        signature = sign_fn(private_key, message)
        sign_t = time.time() - t0
    else:
        sign_t = None

    # Verify
    if verify_fn:
        t0 = time.time()
        verify_fn(public_key, signature, message)
        verify_t = time.time() - t0
    else:
        verify_t = None

    private_size, public_size, signature_size = get_sizes_fn(private_key, public_key, signature)

    mem_after = mem_usage()

    return [
        name,
        f"{keygen_t:.5f}s",
        f"{sign_t:.5f}s" if sign_t else "N/A",
        f"{verify_t:.5f}s" if verify_t else "N/A",
        private_size,
        public_size,
        signature_size if signature_size else "N/A",
        mem_after - mem_before,
    ]


# =============================
# Algorithms
# =============================

# RSA (signing only)
def rsa_bench(bits):
    return benchmark(
        f"RSA-{bits}",
        keygen_fn=lambda: (
            lambda priv=rsa.generate_private_key(public_exponent=65537, key_size=bits):
                (priv, priv.public_key())
        )(),
        sign_fn=lambda priv, msg: priv.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        ),
        verify_fn=lambda pub, sig, msg: pub.verify(
            sig,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        ),
        get_sizes_fn=lambda priv, pub, sig: (
            len(priv.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )),
            len(pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )),
            len(sig)
        )
    )


# ECC ECDSA
def ecc_bench(curve, label):
    return benchmark(
        f"ECC-{label}",
        keygen_fn=lambda: (
            lambda priv=ec.generate_private_key(curve): (priv, priv.public_key())
        )(),
        sign_fn=lambda priv, msg: priv.sign(msg, ec.ECDSA(hashes.SHA256())),
        verify_fn=lambda pub, sig, msg: pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())),
        get_sizes_fn=lambda priv, pub, sig: (
            len(priv.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )),
            len(pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )),
            len(sig),
        )
    )


# Paillier (no sign)
def paillier_bench(bits):
    return benchmark(
        f"Paillier-{bits}",
        
        # FIX: đảo thứ tự public_key, private_key thành private_key, public_key
        keygen_fn=lambda: (
            lambda public_key, private_key: (private_key, public_key)
        )(*paillier.generate_paillier_keypair(n_length=bits)),
        
        sign_fn=None,
        verify_fn=None,

        get_sizes_fn=lambda priv, pub, sig: (
            0,                  # private key not exported here
            len(str(pub.n)),    # public key modulus size
            "N/A"
        )
    )


# =============================
# RUN ALL BENCHMARKS
# =============================

results = []

# RSA
results.append(rsa_bench(1024))
results.append(rsa_bench(2048))
results.append(rsa_bench(4096))

# ECC
results.append(ecc_bench(ec.SECP256R1(), "P-256"))
results.append(ecc_bench(ec.SECP384R1(), "P-384"))

# Paillier
results.append(paillier_bench(1024))
results.append(paillier_bench(2048))

# =============================
# PRINT TABLE
# =============================

headers = [
    "Algorithm",
    "KeyGen Time",
    "Sign Time",
    "Verify Time",
    "Private Key Size",
    "Public Key Size",
    "Signature Size",
    "Memory Δ"
]

print("\n" + tabulate(results, headers=headers, tablefmt="grid"))
