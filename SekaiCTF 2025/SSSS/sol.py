from pwn import *
from sage.all import *
from Crypto.Util.number import *

# io = process(['python3', '/home/team/CodePy/SSSS/chall.py'], level='debug')
io = remote('ssss.chals.sekai.team', 1337, level='debug', ssl=True)
p = 2**256 - 189

F = GF(p)
g = F.multiplicative_generator()

roots = F(1).nth_root(29, all=True)

def calc():
    t = len(roots)
    io.sendline(str(t).encode())

    points = []
    for r in roots:
        io.sendline(str(r).encode())
        points.append((r, int(io.recvline().strip().decode())))

    P = PolynomialRing(F, 'x')
    f = P.lagrange_polynomial(points)

    return f

f1 = calc()
io.sendline(b'0')
io.recvline()

f2 = calc()

coeffs1 = f1.coefficients(sparse=False)
coeffs2 = f2.coefficients(sparse=False)

print(len(coeffs1), len(coeffs2))

for val in coeffs1:
    if val in coeffs2:
        secret = val
        io.sendline(str(secret).encode())
        io.recvline()
        break

# SEKAI{https://youtu.be/XGxIE1hr0w4}