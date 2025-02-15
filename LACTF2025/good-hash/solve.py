from pwn import *
from sage.all import *

x = GF(2)["x"].gen()
F = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)
H = PolynomialRing(F, 'H').gen()

# io = remote("chall.lac.tf", 32222, level = 'debug')
io = process(["python3", "chall.py"], level = 'debug')
io.recvline()

def get_mac(leftextend, rightextend):
    io.sendline(b"1")
    io.sendlineafter(b"input > ", leftextend.hex().encode())
    io.sendlineafter(b"input > ", rightextend.hex().encode())
    mac = io.recvline().strip().decode()
    return bytes.fromhex(mac)

T1 = get_mac(b"", b"\x00" * 16)
T2 = get_mac(b"", b"\x01" * 16)
T3 = get_mac(b"\x01" * 16, b"")
P1 = b"\x00" * 16
P2 = b"\x01" * 16
T1, T2, T3, P1, P2 = map(lambda x: int.from_bytes(x, byteorder='big'), [T1, T2, T3, P1, P2])


def int2field(n: int):
    return F([(n >> i) & 1 for i in range(127, -1, -1)])

def field2int(f):
    n = f.to_integer()  # big endian

    res = 0
    for i in range(128):
        res <<= 1
        res  |= ((n >> i) & 1)
    return res

T1, T2, T3 = map(int2field, [T1, T2, T3])
P1, P2 = map(int2field, [P1, P2])

f = (P1 + P2) * H**2 + T1 + T2
solutions = f.roots(multiplicities=False)

for h in solutions:
    x = PolynomialRing(F, 'x').gen()
    f = (h**3 + h**2) * (x + P2) + T2 + T3

    root = f.roots(multiplicities=False)
    if not root:
        print("None")
    else:
        res = field2int(root[0])
        io.sendline(b"2")
        io.sendlineafter(b"guess > ", res.to_bytes(16, byteorder='big').hex().encode())
        print(io.recvline().decode())
        exit(0)

# lactf{g_d03s_n0t_s7and_f0r_g00d}