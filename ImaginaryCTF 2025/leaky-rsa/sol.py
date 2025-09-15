from pwn import *
from Crypto.Util.number import *
from sage.all import *
from hashlib import sha256
from Crypto.Cipher import AES
import json

io = process(['python3', 'chall.py'], level='debug')
# io = remote('leaky-rsa.chal.imaginaryctf.org', 1337, level='debug')

data = io.recvline().strip().decode()
data = json.loads(data)
n = data['n']
c = data['c']
iv = bytes.fromhex(data['iv'])
ct = bytes.fromhex(data['ct'])

for _ in range(1024):
    io.recvline()
    io.sendline(json.dumps({'c': 0}))
    io.recvline()
key_m = int(io.recvline().strip().decode())

key = sha256(str(key_m).encode()).digest()[:16]
flag = AES.new(key, AES.MODE_CBC, IV=iv).decrypt(ct)
print(flag)
