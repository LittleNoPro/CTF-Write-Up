from collections import Counter
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ns = {}
with open("/home/team/CTF Cryptography/CrewCTF 2025/Inverse with errors only/out.txt", 'r') as f:
    code = f.read()
exec(code, ns)

values = ns["values"]
iv = bytes.fromhex(ns["iv"])
enc = bytes.fromhex(ns["enc"])


def primes(limit):
    s = bytearray(b"\x01")*(limit+1)
    s[:2] = b"\0\0"
    for p in range(2, int(limit**0.5) + 1):
        if s[p]:
            s[p*p:limit+1:p] = b"\0"*(((limit-p*p)//p)+1)
    return [i for i, v in enumerate(s) if v]


reconstructed_d = 0
modulus_product = 1

for prime in primes(2000):
    most_common = Counter(v % prime for v in values).most_common(2)
    if len(most_common) < 2 or most_common[0][1] - most_common[1][1] < 8:
        continue

    d_mod_prime = pow(most_common[0][0], -1, prime)

    increment = ((d_mod_prime - reconstructed_d % prime) * pow(modulus_product, -1, prime)) % prime
    reconstructed_d += modulus_product * increment
    modulus_product *= prime

    if modulus_product.bit_length() >= 1300:
        break

key = sha256(str(reconstructed_d).encode()).digest()
flag = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc), 16)
print(flag.decode())