import time
from tabulate import tabulate
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

LOOPS = 50   # số vòng lặp benchmark


# =============================
# Benchmark (average over loops)
# =============================
def benchmark_avg(name, keygen_fn, sign_fn, verify_fn, get_sizes_fn):

    keygen_times = []
    sign_times = []
    verify_times = []

    private_key = None
    public_key = None
    signature = None

    for _ in range(LOOPS):

        # Key generation
        t0 = time.time()
        private_key, public_key = keygen_fn()
        keygen_times.append(time.time() - t0)

        message = b"Benchmark asymmetric cryptography"

        # Sign
        if sign_fn:
            t0 = time.time()
            signature = sign_fn(private_key, message)
            sign_times.append(time.time() - t0)
        else:
            sign_times.append(0)

        # Verify
        if verify_fn:
            t0 = time.time()
            verify_fn(public_key, signature, message)
            verify_times.append(time.time() - t0)
        else:
            verify_times.append(0)

    # Kích thước key/signature
    priv_size, pub_size, sig_size = get_sizes_fn(private_key, public_key, signature)

    return [
        name,
        LOOPS,
        sum(keygen_times) / LOOPS,
        sum(sign_times) / LOOPS if sign_fn else 0,
        sum(verify_times) / LOOPS if verify_fn else 0,
        priv_size,
        pub_size,
        sig_size if sig_size else 0,
    ]


# =============================
# Algorithms
# =============================
def rsa_bench(bits):
    return benchmark_avg(
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


def ecc_bench(curve, label):
    return benchmark_avg(
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


# =============================
# RUN & STORE RESULTS
# =============================
results = []

# RSA
results.append(rsa_bench(1024))
results.append(rsa_bench(2048))
results.append(rsa_bench(4096))

# ECC
results.append(ecc_bench(ec.SECP256R1(), "P-256"))
results.append(ecc_bench(ec.SECP384R1(), "P-384"))


# =============================
# PRINT TABLE
# =============================
headers = [
    "Algorithm",
    "Loops",
    "KeyGen Time (s)",
    "Sign Time (s)",
    "Verify Time (s)",
    "Private Key Size (bytes)",
    "Public Key Size (bytes)",
    "Signature Size (bytes)",
]

print("\n" + tabulate(results, headers=headers, tablefmt="grid"))


# =============================
# CONVERT TO NANOSECONDS + EXTRACT DATA
# =============================
NS = 1_000_000_000

algos = [r[0] for r in results]

keygen_ns = [r[2] * NS for r in results]
sign_ns   = [r[3] * NS for r in results]
verify_ns = [r[4] * NS for r in results]

priv_sizes = [r[5] for r in results]
pub_sizes  = [r[6] for r in results]
sig_sizes  = [r[7] for r in results]


# =============================
# BAR CHARTS
# =============================
def plot_bar(values, title, ylabel):
    plt.figure(figsize=(10, 5))
    plt.bar(algos, values)
    plt.title(title)
    plt.xlabel("Algorithm")
    plt.ylabel(ylabel)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


plot_bar(keygen_ns, "Key Generation Time (nanoseconds)", "Time (ns)")
plot_bar(sign_ns, "Sign Time (nanoseconds)", "Time (ns)")
plot_bar(verify_ns, "Verify Time (nanoseconds)", "Time (ns)")

plot_bar(priv_sizes, "Private Key Size (bytes)", "Bytes")
plot_bar(pub_sizes, "Public Key Size (bytes)", "Bytes")
plot_bar(sig_sizes, "Signature Size (bytes)", "Bytes")
