from pwn import *
from Crypto.Util.number import *
from sympy.ntheory.modular import solve_congruence
import json
import hashlib

io = remote("challs.nusgreyhats.org", 33301, level = 'debug')
io.recvline()

p, g, y = map(int, io.recvline().strip().split())
k = int(io.recvline().strip().split()[1])
r = pow(g, k, p)

target = bytes_to_long(b"gib flag pls uwu")

io.sendlineafter(b"> ", b"2")
msg1 = b"dangminhtu"
io.sendline(json.dumps({"m": bytes_to_long(msg1)}).encode())
io.recvuntil(b"Here's your uwu signature! ")
s1 = json.loads(io.recvline().strip().decode())

# io.sendlineafter(b"> ", b"2")
# msg2 = b"dangminhtu2006"
# io.sendline(json.dumps({"m": bytes_to_long(msg2)}).encode())
# io.recvuntil(b"Here's your uwu signature! ")
# s2 = json.loads(io.recvline().strip().decode())


h = bytes_to_long(hashlib.sha256(msg1).digest())
s = s1
mod = p - 1
r_inv = inverse(r, mod)
x = (h - s * k) * r_inv % mod

assert y == pow(g, x, p)

target = b"gib flag pls uwu"
m = bytes_to_long(target)
h = bytes_to_long(hashlib.sha256(target).digest())
r = pow(g, k, p)
s = ((h - x * r) * inverse(k, p - 1)) % (p - 1)

io.sendlineafter(b'> ', b'1')
io.sendline(json.dumps({
    "m": int(m),
    "r": int(r),
    "s": int(s)
}).encode())
io.recvall()


# grey{h_h_H_h0wd_y0u_Do_tH4T_OMO}
# https://crypto.stackexchange.com/questions/1479/elgamal-signature-scheme-recovering-the-key-when-reusing-randomness