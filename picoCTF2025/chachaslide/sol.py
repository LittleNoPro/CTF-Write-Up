from sage.all import *
from pwn import *
from Crypto.Util.number import *
import struct

p = (1 << 130) - 5
R = PolynomialRing(GF(p), 'x')
x = R.gen()

conn = remote("activist-birds.picoctf.net", 51396, level='debug')
conn.recvuntil(b"Ciphertext (hex): ")
c1_hex = conn.recvline().decode().strip()
conn.recvuntil(b"Ciphertext (hex): ")
c2_hex = conn.recvline().decode().strip()

p1 = b"Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?"
p2 = b"That means it protects both the confidentiality and integrity of data!"
goal = b"But it's only secure if used correctly!"

c1 = bytes.fromhex(c1_hex)
c2 = bytes.fromhex(c2_hex)

ciphertext1 = c1[:-28]
tag1 = c1[-28:-12]
nonce = c1[-12:]

ciphertext2 = c2[:-28]
tag2 = c2[-28:-12]

keystream = xor(ciphertext1, p1)
goal_ciphertext = xor(goal, keystream[:len(goal)])

def divceil(divident, divisor):
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))

def pad16(data):
    if len(data) % 16 == 0:
        return bytearray(0)
    else:
        return bytearray(16-(len(data)%16))

def make_poly(msg):
    aad = b""
    padded = aad + pad16(aad)
    padded += msg + pad16(msg)
    padded += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(msg))

    f = 0
    for i in range(0, divceil(len(padded), 16)):
        n = padded[i*16:(i+1)*16] + b"\x01"
        n += (17 - len(n)) * b"\x00"
        f = (f + int.from_bytes(n, "little")) * x

    return f

def find_r_s():
    f1 = make_poly(ciphertext1)
    f2 = make_poly(ciphertext2)

    res = []
    for k in range(-4, 5):
        rhs = int.from_bytes(tag1, "little") - int.from_bytes(tag2, "little")  + 2**128 * k
        f = rhs - (f1 - f2)
        for r, _ in f.roots():
            if int(r).bit_length() <= 124:
                s = (int.from_bytes(tag1, "little") - int(f1(r))) % (1 << 128)
                res.append((r, s))

    assert len(res) == 1

    return res[0]

r, s = find_r_s()

def poly1305_mac(msg, r, s):
    f = make_poly(msg)
    tag = (int(f(r)) + s) % (1 << 128)
    tag = int(tag).to_bytes(16, "little")
    return tag

tag_goal = poly1305_mac(goal_ciphertext, r, s)
final_ciphertext = goal_ciphertext + tag_goal + nonce


conn.sendlineafter(b"What is your message? ", final_ciphertext.hex().encode())
print(conn.recvall())

# Flag : picoCTF{7urn_17_84ck_n0w_5cde9e39}