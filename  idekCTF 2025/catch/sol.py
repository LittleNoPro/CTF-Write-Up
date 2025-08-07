import json
import hashlib
from Crypto.Cipher import AES
from itertools import permutations
from Crypto.Util.Padding import pad
from sympy import primerange, isprime
from pwn import *
from string import *
from sage.all import *
from randcrack import *
from Crypto.Util.number import *

io = remote('catch.chal.idek.team', 1337, level='debug')
# io = process(['python3', '/home/team/CodePy/chall.py'], level='debug')

for round in range(20):
    io.recvuntil(b'Co-location: ')
    human_pos = eval(io.recvline().strip().decode())
    io.recvuntil(b'Cat\'s hidden mind: ')
    cat_mind = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b'Cat now at: ')
    cat_pos = eval(io.recvline().strip().decode())

    path = b''

    step = [cat_mind[i:i+8] for i in range(0, 1000, 8)]
    lst = []
    for _ in range(30):
        for st in step:
            M = matrix(ZZ, 2, 2, [int.from_bytes(st[i:i+2], "big") for i in range(0, 8, 2)])
            res = vector(ZZ, [cat_pos[0], cat_pos[1]])
            res = M.solve_right(res)
            ok = True
            for val in res:
                if val != int(val):
                    ok = False
                    break
            if ok:
                cat_pos = (int(res[0]), int(res[1]))
                path = st + path

    io.sendlineafter(b'Path to recall (hex): ', path.hex().encode())
    io.recvline()

io.recvuntil(b'within: ')
flag = io.recvline().strip().decode()
print(flag)