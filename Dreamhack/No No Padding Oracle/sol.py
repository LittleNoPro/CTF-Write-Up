import json
import base64
from pwn import *
from tqdm import *
from Crypto.Cipher import AES

io = process(['python3', 'chal.py'])
# io = remote('host8.dreamhack.games', 18925)

def register(name):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Name: ', name)
    resp = io.recvline().strip().split(b': ')[-1]
    return base64.b64decode(resp.decode())

def login(name, token):
    token = base64.b64encode(token)
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Name: ', name)
    io.sendlineafter(b'Token: ', token)
    resp = io.recvline().strip()
    return resp

token = register(b'a')
iv, block0, block1 = [token[i:i+16] for i in range(0, len(token), 16)]

target = b'{"name":"a","isAdmin":1}'
after_block1 = xor(block0, b'sAdmin": false}\x00')
new_block0 = xor(after_block1, b'dmin":1}\x00\x00\x00\x00\x00\x00\x00\x00')

new_iv = b''
for ch in trange(256):
    _iv = bytes([ch]) + b'\x00' * 15
    resp = login(b'a', _iv + new_block0 + block1)
    if b'Expecting property name enclosed in double quotes: line 1 column 2 (char 1)' in resp:
        new_iv = bytes([ch])
        print("Found bytes 1")
        break

for ch in trange(256):
    _iv = new_iv + bytes([ch]) + b'\x00' * 14
    resp = login(b'a', _iv + new_block0)
    if b'name' in resp:
        new_iv += bytes([ch])
        print('FOUND')
        break

for _ in trange(2, 16):
    for ch in range(256):
        padding = b'\x00' * (16 - len(new_iv) - 1)
        _iv = new_iv[:-1] + xor(xor(new_iv[-1], b'}'), b' ') + bytes([ch]) + padding

        resp = login(b'a', _iv + new_block0)
        if b'name' in resp:
            new_iv = _iv[:len(new_iv) + 1]
            print(new_iv)
            break

after_block0 = xor(new_iv, b'{              }')
new_iv = xor(after_block0, target[:16])

resp = login(b'a', new_iv + new_block0 + block1)
io.sendlineafter(b'> ', b'3')
flag = io.recvline().decode().strip()
print(flag)

