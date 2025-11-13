# -*- coding: utf-8 -*-
"""
Mô phỏng ước lượng thời gian brute-force cho nhiều độ dài mật khẩu
(4, 8, 12) và 5 case charset khác nhau trên GPU RTX 4090.
"""

# Tốc độ hash trên RTX 4090 (hash/giây) - ví dụ từ Hashcat
hash_speeds = {
    "MD5":               150_000_000_000,   # 150 GH/s
    "SHA-2 (SHA256)":     20_000_000_000,   # 20 GH/s
    "SHA-3 (SHA3-256)":   10_000_000_000,   # 10 GH/s
}

# Các độ dài mật khẩu cần tính (thêm 4 và 12, giữ 8)
password_lengths = [4, 8, 12]

# Xác định số ký tự theo từng case
charset_sizes = {
    "case1_numbers":                             10,   # 0-9
    "case2_lowercase":                           26,   # a-z
    "case3_numbers+lowercase":                   36,   # a-z, 0-9
    "case4_numbers+lowercase+uppercase":         62,   # a-z, A-Z, 0-9
    "case5_numbers+lowercase+uppercase+special": 95,   # printable ASCII ~95
}

def estimate_bruteforce_time(num_characters, length, hash_speed):
    """
    Ước lượng thời gian brute-force.
    Trả về: avg_time_sec, max_time_sec
    """
    total_passwords = num_characters ** length
    max_time_sec = total_passwords / hash_speed
    avg_time_sec = max_time_sec / 2
    return avg_time_sec, max_time_sec

def format_time(sec):
    """Định dạng thời gian dễ đọc"""
    if sec < 1:
        return f"{sec:.6f} s"
    elif sec < 60:
        return f"{sec:.2f} s"
    elif sec < 3600:
        return f"{sec/60:.2f} min"
    elif sec < 86400:
        return f"{sec/3600:.2f} h"
    elif sec < 31536000:
        return f"{sec/86400:.2f} days"
    else:
        return f"{sec/31536000:.1f} years"

# In tiêu đề (thêm cột Length)
print(f"{'Case':<45} {'Length':<7} {'Hash':<18} {'Avg Time':<20} {'Max Time':<20}")
print("-" * 110)

for case_name, num_chars in charset_sizes.items():
    for length in password_lengths:
        for hash_name, speed in hash_speeds.items():
            avg_sec, max_sec = estimate_bruteforce_time(num_chars, length, speed)
            avg_str = format_time(avg_sec)
            max_str = format_time(max_sec)
            print(f"{case_name:<45} {length:<7} {hash_name:<18} {avg_str:<20} {max_str:<20}")
