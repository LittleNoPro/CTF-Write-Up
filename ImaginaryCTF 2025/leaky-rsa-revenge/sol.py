from pwn import *
from Crypto.Util.number import *
from sage.all import *
from hashlib import sha256
from Crypto.Cipher import AES
import json

while True:
    io = process(['python3', 'chall.py'])
    # io = remote('leaky-rsa-revenge.chal.imaginaryctf.org', 1337, level='debug')

    data = io.recvline().strip().decode()
    data = json.loads(data)
    N = data['n']
    c = data['c']
    e = 65537
    iv = bytes.fromhex(data['iv'])
    ct = bytes.fromhex(data['ct'])

    if N % 16 != 15:
        io.close()
        continue

    upper_limit = N
    lower_limit = 0
    i = 1
    while i <= 1024:
        idx = json.loads(io.recvline().strip().decode())['idx']

        chosen_ct = long_to_bytes(c * pow(2**(i+idx), e, N) % N)

        io.sendline(json.dumps({'c': bytes_to_long(chosen_ct)}).encode())
        output = json.loads(io.recvline().strip().decode())['b']

        if output == 0:
            print('0', end='')
            upper_limit = (lower_limit + upper_limit) // 2
        elif output == 1:
            print('1', end='')
            lower_limit = (lower_limit + upper_limit) // 2
        i += 1

    for offset in range(-10000, 10000):
        m = lower_limit + offset
        key = sha256(str(m).encode()).digest()[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        flag = cipher.decrypt(ct)
        if b'ictf' in flag:
            print(flag)
            exit()


# ictf{p13cin9_7h3_b1t5_t0g37her_7d092f5d43ebbf6fa60fba8c9e9ac4466daba9a71d04def7e5bf09bcce5649c8}