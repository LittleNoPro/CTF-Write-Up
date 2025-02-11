from pwn import *
from Crypto.Util.number import *
from math import *
import random

e = 65537

def find_prime(start):
    k = start // e
    while True:
        p = k * e + 1
        if p.bit_length() == 64 and isPrime(p):
            return p
        k += random.randint(1, 100)

p = find_prime(2**63)

while True:
    q = find_prime(2**63 + random.randint(10**6, 10**9))
    if q != p:
        break

phi = (p - 1) * (q - 1)

print(f"p = {p}")
print(f"q = {q}")

conn = remote("chall.lac.tf", 31176, level = "debug")
conn.recvuntil(b"Input p: ")
conn.sendline(str(p))
conn.recvuntil(b"Input q: ")
conn.sendline(str(q))

conn.recvline()

# lactf{actually_though_whens_the_last_time_someone_checked_for_that}