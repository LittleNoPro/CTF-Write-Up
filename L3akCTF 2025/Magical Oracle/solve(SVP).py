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

B = p >> k + 1
M = Matrix(QQ, d + 2, d + 2)
for i in range(d):
    M[i, i] = QQ(p)
    M[d, i] = QQ(ts[i])
    M[d + 1, i] = QQ(zs[i])
M[d, d] = QQ(B) / QQ(p)
M[d + 1, d + 1] = QQ(B)

M = M.LLL()
for row in M:
    if row[-1] == B:
        alpha = int((-row[-2] * QQ(p) / QQ(B)).round()) % p
    if row[-1] == -B:
        alpha = int((row[-2] * QQ(p) / QQ(B)).round()) % p

iv = enc_flag[:16]
ct = enc_flag[16:]
key = hashlib.sha256(str(alpha).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct)
print(flag)


# L3AK{hnp_BBB_cvp_4_the_w1n}