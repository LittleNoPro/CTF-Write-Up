import json
from pwn import *
from sage.all import *
from Crypto.Util.number import *

x = GF(2)["x"].gen()
F = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)
H = PolynomialRing(F, 'H').gen()

def int2field(n: int):
    return F([(n >> i) & 1 for i in range(127, -1, -1)])

def field2int(f):
    n = f.to_integer()  # big endian

    res = 0
    for i in range(128):
        res <<= 1
        res  |= ((n >> i) & 1)
    return res


# io = process(['python3', 'chal.py'], level = 'debug')
io = remote('host8.dreamhack.games', 22948, level='debug')

def sign_up(name):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Username: ', name)
    resp = io.recvline().strip().decode().split(': ')[-1]
    io.recvline()
    return bytes.fromhex(resp)

def sign_in(name, passcode, token):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Username: ', name)
    io.sendlineafter(b'Passcode (Enter if none): ', passcode)
    io.sendlineafter(b'Token: ', token.hex().encode())
    resp = io.recvline().strip().decode()
    return resp

def bytes2field(text):
    return int2field(int.from_bytes(text, byteorder='big'))

target = b'{"username": "admin", "passcode": "This_is_super_safe_passcode_never_try_to_enter_q1w2w3r4"}'
name1 = '😊😊😊😊😊🤔aaaa'
plaintext1 = json.dumps({"username": name1}).encode("ascii")

L = len(target)
while len(target) % 16 != 0:
    plaintext1 += b'\x00'
    target += b'\x00'
for _ in range(8):
    plaintext1 += b'\x00'
    target += b'\x00'
plaintext1 += L.to_bytes(8, 'big')
target += L.to_bytes(8, 'big')

tag1 = sign_up(name1)

p1 = b'{"username": "c"'
p2 = b'{"username": "b"'
t1 = sign_up(b'c')
t2 = sign_up(b'b')

p1, p2, t1, t2 = bytes2field(p1), bytes2field(p2), bytes2field(t1), bytes2field(t2)

fx = (p1 + p2) * H**3 + (t1 + t2)
sols = fx.roots(multiplicities=False)
h = sols[1]

tag = bytes2field(tag1)
exp = 7
for i in range(len(target) // 16):
    b1 = target[i*16:(i+1)*16]
    b2 = plaintext1[i*16:(i+1)*16]
    b1, b2 = bytes2field(b1), bytes2field(b2)
    tag += h**exp * (b1 + b2)
    exp -= 1

tag = long_to_bytes(field2int(tag))

resp = sign_in(b'admin', b'This_is_super_safe_passcode_never_try_to_enter_q1w2w3r4', tag)

# Get Flag
io.sendlineafter(b'> ', b'4')
flag = io.recvline().strip().decode()
print(flag)


