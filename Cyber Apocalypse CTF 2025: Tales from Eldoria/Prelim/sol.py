import ast
from hashlib import *
from Crypto.Cipher import AES
from math import lcm

n = 0x1337
e = 0x10001

with open('/home/team/CodePy/Cyber Apocalypse CTF 2025: Tales from Eldoria/Prelim/tales.txt', 'r') as f:
    scrambled_message = ast.literal_eval(f.readline().split('=')[1].strip())

enc_flag = "ca9d6ab65e39b17004d1d4cc49c8d6e82f9fa7419824d07096d41ee41f0578fe6835da78bc31dd46587a86377883e0b7"
enc_flag = bytes.fromhex(enc_flag)

def scramble(a, b):
    return [b[a[i]] for i in range(n)]

def super_scramble(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = scramble(b, a)
        a = scramble(a, a)
        e >>= 1
    return b

order = 1
for i in range(1, n + 1):
    order *= i
message = super_scramble(scrambled_message, pow(e, -1, order))

key = sha256(str(message).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)

print(flag)

# HTB{t4l3s_fr0m___RS4_1n_symm3tr1c_gr0ups!}
