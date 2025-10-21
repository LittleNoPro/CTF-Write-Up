from pwn import *
import hashlib
from Crypto.Util.number import *
from math import gcd

io = remote('crypto3.cscv.vn', 31337, level='debug')

io.recvline()
prefix = io.recvline().strip().decode().split('=')[-1]
prefix = bytes.fromhex(prefix)

final_nonce = b''
for _nonce in range(10000000):
    nonce = long_to_bytes(_nonce)
    h = hashlib.sha256(prefix + nonce).hexdigest()
    if h.startswith('000000'):
        final_nonce = nonce
        break

io.sendlineafter(b'<hex>\n', b'NONCE ' + final_nonce.hex().encode())
io.recvuntil(b'compatibility.\n')

users = ["2", "22", "3", "33", "4", "44", "9", "99"]
sig = {}
for u in users:
    io.sendline(b'REGISTER ' + u.encode() + b' ' + u.encode())
    io.recvline()
    io.sendline(b'LOGIN ' + u.encode() + b' ' + u.encode())
    sig[u] = int(io.recvline().strip().decode().split("||")[-1])

def calc(x: str, y: str) -> int:
    return sig[x+x] * sig[y] - sig[y+y] * sig[x]

X1 = calc("2", "3")
X2 = calc("4", "9")
X3 = calc("3", "4")

n = 0
for val in (X1, X2, X3):
    n = gcd(n, abs(val)) if n else abs(val)

admin_name = "campus_admin_2025"
aa = admin_name + admin_name

io.sendline(b'REGISTER ' + aa.encode() + b' ' + aa.encode())
io.recvline()
io.sendline(b'LOGIN ' + aa.encode() + b' ' + aa.encode())
S_aa = int(io.recvline().strip().decode().split("||")[-1])

def try_u(u):
    io.sendline(b'REGISTER ' + u.encode() + b' ' + u.encode())
    io.recvline()
    io.sendline(b'LOGIN ' + u.encode() + b' ' + u.encode())
    S_u = int(io.recvline().strip().decode().split("||")[-1])

    uu = u + u
    io.sendline(b'REGISTER ' + uu.encode() + b' ' + uu.encode())
    io.recvline()
    io.sendline(b'LOGIN ' + uu.encode() + b' ' + uu.encode())
    S_uu = int(io.recvline().strip().decode().split("||")[-1])
    return S_u, S_uu

S_u, S_uu = try_u("a" * len(admin_name))

S_admin = (S_aa * S_u * inverse(S_uu, n)) % n

token = admin_name.encode() + b'||' + str(S_admin).encode()
io.sendline(b'GETFLAG ' + token)
flag = io.recvline()
print(flag)