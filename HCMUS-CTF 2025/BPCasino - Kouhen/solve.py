from pwn import *
from Crypto.Util.number import *

# io = process(["python3", "/home/team/CodePy/HCMUS-CTF/BPCasino - Kouhen/chall.py"], level='debug')
io = remote('chall.blackpinker.com', 33545)

def get_enc(pt):
	io.sendlineafter(b'Plaintext (hex) ', pt.hex().encode())
	res = bytes.fromhex(io.recvline().strip().decode())
	return res

def split(arr, size_per_chunk):
	return [arr[i:i+size_per_chunk] for i in range(0, len(arr), size_per_chunk)]

for i in range(3*37):
	pt = b'\x00'*32
	res = get_enc(pt)
	blocks = split(res, 16)
	blocks = [split(b, 4) for b in blocks]
	if blocks[0][1][0] ^ blocks[0][1][1] ^ blocks[1][1][0] ^ blocks[1][1][1] == 0:
		guess = 1
	else:
		guess = 0
	io.sendlineafter(b'Guess what? ', str(guess).encode())

flag = io.recvline().strip().decode()
print(flag)

# HCMUS-CTF{you_h4ve_obs3rv4t1on_for_PRF}