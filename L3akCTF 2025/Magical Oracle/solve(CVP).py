from pwn import *
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime
from secrets import randbelow
from sage.all import *

io = remote('34.59.96.214', 11000, level='debug')
# io = process(['python3', '/home/team/CodePy/L3akCTF/Magical Oracle/chal.py'], level='debug')

# Show parameters
io.sendlineafter(b'Choose option: ', b'3')
io.recvline()
p = int(io.recvline().decode().strip().split('=')[-1])
n = int(io.recvline().decode().strip().split('=')[-1])
k = int(io.recvline().decode().strip().split('=')[-1])
d = int(io.recvline().decode().strip().split('=')[-1])


# Show encrypted flag
io.sendlineafter(b'Choose option: ', b'2')
io.recvline()
enc_flag = io.recvline().decode().strip().split(': ')[-1]
enc_flag = base64.b64decode(enc_flag)

# Get query
ts, zs = [], []
for _ in range(d):
    io.sendlineafter(b'Choose option: ', b'1')
    io.recvline()
    query = io.recvline().decode().strip().split(': ')[-1]
    query = query.split(', ')
    t = int(query[0].split('=')[-1])
    leak = int(query[1].split('=')[-1])
    ts.append(t)
    zs.append(leak)

M = Matrix(QQ, d + 1, d + 1)
for i in range(d):
    M[i, i] = p
    M[d, i] = ts[i]
M[d, d] = QQ(1) / QQ(p)

def babai_cvp(B, t, perform_reduction=True):
    if perform_reduction:
        B = B.LLL(delta=0.75)

    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]

    return t - b

u = babai_cvp(M, vector(zs + [0]))
alpha = int((u[-1] * p).round()) % p

iv = enc_flag[:16]
ct = enc_flag[16:]
key = hashlib.sha256(str(alpha).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct)
print(flag)


# L3AK{hnp_BBB_cvp_4_the_w1n}