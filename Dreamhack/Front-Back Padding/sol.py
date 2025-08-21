from pwn import *

# io = process(['python3', '/home/team/CodePy/chal.py'], level='debug')
io = remote('host8.dreamhack.games', 22711, level='debug')

prefix = b'DreamHack_prefix'
suffix = b'happy_Amo_suffix'

def FB_pad(msg):
    r = -len(msg)%16 + 16
    n1 = r // 2
    n2 = r - n1
    return prefix[:n1] + msg + suffix[-n2:]

def FB_unpad(msg):
    if len(msg) % 16 != 0:
        return False, "message length is invalid"
    n1 = 0
    n2 = 0
    while n1 < 16 and msg[:n1 + 1] == prefix[:n1 + 1]:
        n1 += 1
    while n2 < 16 and msg[-n2 - 1:] == suffix[-n2 - 1:]:
        n2 += 1
    if n1 + n2 < 16:
        return False, "wrong padding"
    return True, msg[n1:-n2]

payload = b'k_prefixhappy_Am'
io.sendlineafter(b' > ', b'1')
io.sendlineafter(b'input your message(hex) > ', payload.hex().encode())
ct = io.recvline().strip().decode().split(': ')[-1]
assert len(ct) == 64
ct1, ct2 = ct[:32], ct[32:]

io.sendlineafter(b' > ', b'3')
io.recvuntil(b'flag: ')
flag_enc = io.recvline().strip().decode()

payload = b''
io.sendlineafter(b' > ', b'1')
io.sendlineafter(b'input your message(hex) > ', payload.hex().encode())
enc = io.recvline().strip().decode().split(': ')[-1]
assert len(enc) == 32

payload = ct1 + "00"*16 + enc + ct1 + ct2
io.sendlineafter(b' > ', b'2')
io.sendlineafter(b'input your message(hex) > ', payload.encode())
res = io.recvline().strip().decode().split(': ')[-1]
res = bytes.fromhex(res[32:64])
iv = xor(res, b'DreamHaco_suffix')
iv = iv.hex()

payload = ct1 + iv + flag_enc + ct1 + ct2
io.sendlineafter(b' > ', b'2')
io.sendlineafter(b'input your message(hex) > ', payload.encode())
res = io.recvline().strip().decode().split(': ')[-1]
flag = bytes.fromhex(res[32:-32])
print(flag)