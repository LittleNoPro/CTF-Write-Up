from pwn import *
import random, json

io = remote("challenge.cnsc.com.vn", 30429, level='debug')
N = 128

rand = random.Random()
rand.seed("Wanna Win?")
As = [[rand.randbytes(N) for _ in range(N)] for _ in range(64)]

def calc(A, b):
    x = [0] * N
    for j in range(N):
        m = 10**9
        for i in range(N):
            m = min(m, b[i] - A[i][j])
        x[j] = m % 256
    return bytes(x)

for r in range(64):
    io.recvuntil(b"b = ")
    b = json.loads(io.recvline().decode().strip())
    io.recvuntil(b"x = ")
    x = calc(As[r], b)
    io.sendline(x.hex())

print(io.recvall())

# W1{W3I1-l_THiNK_lts_3ASler_Than_nOrmAL-Lln3Ar_41gebra_problem0}