from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime, inverse
from hashlib import sha256
import base64

def solve():
    io = remote('challenge.cnsc.com.vn', 32730, level='debug')

    io.recvuntil(b"N = ")
    N_b85 = io.recvline().strip()
    N_bytes = base64.a85decode(N_b85)

    found_byte = None
    prime_N = 0

    for b in range(256):
        candidate_bytes = bytearray(N_bytes)
        candidate_bytes[0] = b
        candidate_N = bytes_to_long(candidate_bytes)

        if isPrime(candidate_N):
            found_byte = b
            prime_N = candidate_N
            break

    if found_byte is None:
        io.close()
        return None

    d = inverse(0x10001, prime_N - 1)

    target = b"1_d4r3_y0u_70_519n_7h15_3x4c7_51x7y_f0ur_by73_57r1n9_w17h_my_k3y"
    target = bytes_to_long(sha256(target).digest())

    sig_forged_int = pow(target, d, prime_N)

    io.sendlineafter(b"Sign(0) or Verify(1): ", b"0")

    payload = b'!!!!!' * 15 + b'!!!!' + bytes([found_byte])

    io.sendlineafter(b"base85: \n", payload)

    io.sendlineafter(b"Sign(0) or Verify(1): ", b"1")

    sig_bytes = long_to_bytes(sig_forged_int)
    if len(sig_bytes) < 384:
        sig_bytes = b'\x00' * (384 - len(sig_bytes)) + sig_bytes

    sig_payload = base64.a85encode(sig_bytes)
    io.sendlineafter(b"base85\n", sig_payload)

    result = io.recvline()
    if b"Wrong" in result or b"Huh" in result:
        return None

    return result

while True:
    flag = solve()
    if flag is not None:
        print(flag)
        break

# W1{I_ShOUlD-u53-PYTHon-t0-lmPI3M3n7-CRYp7O9rApHIC_SCH3M3S..8bf}