import hashlib
import psutil
import time

hashing_algorithms = [
    'sha256', 'sha224', 'sha384', 'sha512',
    'md5', 'sha3_512', 'sha3_384', 'sha3_256', 'sha3_224', 'blake2b'
]

def measure_hash_performance(input_bytes: bytes, algo_name: str, iterations: int = 10000):
    proc = psutil.Process()                 # tiến trình hiện tại
    func = getattr(hashlib, algo_name)      # lấy hàm hash động

    # Warm-up để loại bỏ chi phí khởi tạo ban đầu
    func(input_bytes).digest()

    # Ghi nhận thông tin trước khi đo
    cpu_before = proc.cpu_times()
    mem_before = proc.memory_info().rss / (1024 ** 2)   # MB
    t0 = time.perf_counter()

    # Thực hiện hashing nhiều lần
    for _ in range(iterations):
        func(input_bytes).digest()

    # Ghi nhận thông tin sau khi đo
    t1 = time.perf_counter()
    cpu_after = proc.cpu_times()
    mem_after = proc.memory_info().rss / (1024 ** 2)    # MB

    # Tính toán chênh lệch
    delta_user = cpu_after.user - cpu_before.user
    delta_system = cpu_after.system - cpu_before.system
    delta_cpu = delta_user + delta_system
    elapsed_wall = t1 - t0
    delta_mem = mem_after - mem_before

    cpu_usage_percent = (delta_cpu / elapsed_wall) * 100 if elapsed_wall > 0 else 0

    return {
        "algo": algo_name,
        "iterations": iterations,
        "delta_cpu": delta_cpu,
        "elapsed_wall": elapsed_wall,
        "delta_mem": delta_mem,
        "avg_cpu_per_iter": delta_cpu / iterations,
        "avg_wall_per_iter": elapsed_wall / iterations,
        "cpu_usage_percent": cpu_usage_percent,
    }

if __name__ == "__main__":
    input_text = "Hello, World!"
    input_bytes = input_text.encode("utf-8")

    iterations = 500000
    print(f"{'Algorithm':<12} {'iters':>6} {'CPU(s)':>10} {'Wall(s)':>10} {'MemΔ(MB)':>10} {'CPU/iter':>12} {'Wall/iter':>12} {'CPU(%)':>8}")
    print("-" * 90)

    for algo in hashing_algorithms:
        try:
            res = measure_hash_performance(input_bytes, algo, iterations=iterations)
        except Exception as e:
            print(f"{algo:<12} ERROR: {e}")
            continue

        print(f"{res['algo']:<12} {res['iterations']:6d} "
              f"{res['delta_cpu']:10.6f} {res['elapsed_wall']:10.6f} {res['delta_mem']:10.6f} "
              f"{res['avg_cpu_per_iter']:12.9f} {res['avg_wall_per_iter']:12.9f} {res['cpu_usage_percent']:8.2f}")


 
