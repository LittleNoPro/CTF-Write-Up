import base64
import json
from pwn import *

# io = process(['python3', '/home/team/CTF Cryptography/crypto/challenge'], level='debug')
io = remote('challs.glacierctf.com', 13387, level='debug')

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"> ", b"A")
token = io.recvline_contains(b"Here is your token: ").strip().decode().split("token: ")[1]
iv = base64.b64decode(json.loads(token)['iv'])
ct = base64.b64decode(json.loads(token)['ct'])

modified_iv = bytearray(iv)
modified_iv[6] = modified_iv[6] ^ ord('0') ^ ord('1')
modified_token = json.dumps({
    'iv': base64.b64encode(bytes(modified_iv)).decode(),
    'ct': base64.b64encode(ct).decode()
})

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", modified_token.encode())
io.recvline()
response = io.recvline().decode()
