import hashlib
import secrets

from Crypto.Cipher import AES
from Crypto.Util.number import getPrime as get_prime
from Crypto.Util.Padding import pad

flag = b"crew{*** REDACTED ***}"

bits = 1024
d = get_prime(bits)
values = []

for _ in range(30000):
    n = secrets.randbits(1024) | (1 << 1024)
    values.append(pow(d, -1, n))

key = hashlib.sha256(str(d).encode()).digest()
flag = pad(flag, 16)

cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv.hex()
enc = cipher.encrypt(flag).hex()

print(f"{values = }")
print(f"{iv = }")
print(f"{enc = }")
