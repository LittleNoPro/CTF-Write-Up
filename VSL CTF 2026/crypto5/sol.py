from pwn import *
import time
import string
import binascii

# Cấu hình kết nối
HOST = 'localhost' # Thay đổi thành IP của server nếu cần
PORT = 6668

# Bộ ký tự cho phép
ALLOWED_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase
KEY_LENGTH = 16

# Hàm tiện ích XOR
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def solve():
    # Kết nối tới server
    r = remote(HOST, PORT)

    # Bỏ qua banner
    r.recvuntil(b"queries available.")

    master_key_guessed = []

    # IV cố định (16 bytes 00)
    # IV này sẽ được dùng lại (Reuse) để Keystream không đổi
    IV_HEX = "00" * 16
    IV_BYTES = bytes.fromhex(IV_HEX)

    print("[*] Đang lấy Keystream cơ sở...")

    # Bước 1: Lấy Keystream
    # Gửi Ciphertext toàn 0 để lấy Keystream (P = 0 ^ K -> P = K)
    ZERO_CIPHER = "00" * 16 # độ dài khớp với key length 16 byte để lấy đủ keystream

    r.recvuntil(b"iv: ")
    r.sendline(IV_HEX.encode())
    r.recvuntil(b"ciphertext: ")
    r.sendline(ZERO_CIPHER.encode())

    r.recvuntil(b"plaintext: ")
    keystream_hex = r.recvline().strip().decode()
    KEYSTREAM = bytes.fromhex(keystream_hex)

    print(f"[+] Keystream thu được: {KEYSTREAM.hex()}")
    print("[*] Bắt đầu tấn công Timing Attack từng byte...")

    # Bước 2: Tấn công từng byte
    for i in range(KEY_LENGTH):
        max_time = 0
        best_char = None

        # Thử từng ký tự có thể
        # Lưu ý: Trong môi trường mạng thật (jitter), bạn có thể cần đo nhiều lần
        # nhưng giới hạn 1000 queries rất chặt, nên ta chỉ đo 1 lần/char.

        candidates_times = {}

        for char in ALLOWED_CHARS:
            char_byte = char.encode()[0]

            # Tạo forged plaintext:
            # - Các byte từ 0 đến i-1: Phải ĐÚNG (đã tìm được)
            # - Byte i: Là ký tự đang đoán (char)
            # - Các byte sau: Không quan trọng (để 0)

            fake_plaintext_list = bytearray(KEYSTREAM) # Khởi tạo nháp

            # Điền các byte đã tìm được
            for idx, known_b in enumerate(master_key_guessed):
                fake_plaintext_list[idx] = known_b

            # Điền byte đang đoán
            fake_plaintext_list[i] = char_byte

            # Tính toán Ciphertext cần gửi: C = P ^ K
            # Vì P ta muốn là fake_plaintext_list, K là KEYSTREAM
            forged_ciphertext = xor_bytes(fake_plaintext_list, KEYSTREAM)

            # Gửi và đo thời gian
            try:
                r.recvuntil(b"iv: ") # Chờ prompt
                r.sendline(IV_HEX.encode())

                r.recvuntil(b"ciphertext: ")

                start_time = time.perf_counter() # Bấm giờ
                r.sendline(forged_ciphertext.hex().encode())

                response = r.recvline() # Nhận phản hồi "plaintext: ..." hoặc banner Win
                end_time = time.perf_counter() # Dừng giờ

                elapsed = end_time - start_time
                candidates_times[char] = elapsed

                # Kiểm tra xem có trúng luôn không (nếu là byte cuối hoặc may mắn)
                if b"UNLOCKED" in response or b"Treasure" in r.recv(timeout=0.1):
                    print(f"\n[!!!] DONE! Key found early: {''.join([chr(c) for c in master_key_guessed]) + char}")
                    r.interactive()
                    return

            except EOFError:
                print("Server đóng kết nối bất ngờ.")
                return

        # Tìm ký tự có thời gian phản hồi lâu nhất
        best_char = max(candidates_times, key=candidates_times.get)
        master_key_guessed.append(ord(best_char))

        print(f"Byte {i}: '{best_char}' (Time: {candidates_times[best_char]:.6f}s) | Current Key: {''.join([chr(c) for c in master_key_guessed])}")

    # Gửi lần cuối để nhận flag
    final_key = "".join([chr(c) for c in master_key_guessed])
    print(f"[*] Final Key Candidates: {final_key}")

    # Thử gửi key đúng
    final_ciphertext = xor_bytes(final_key.encode(), KEYSTREAM)
    r.sendline(IV_HEX.encode())
    r.sendline(final_ciphertext.hex().encode())
    r.interactive()

if __name__ == "__main__":
    solve()