from pwn import *
from Crypto.Util.number import *
import hashlib
import base64

io = process(['python3', '/home/team/CodePy/feistier-network/chal.py'], level='debug')

io.sendlineafter(b'give me your best shot >:)\t', base64.b64encode(b'\x00'))
seed = bytes_to_long(b'\x00')
print(seed)