from pwn import *
from Crypto.Util.number import *
from sage.all import *
import itertools

p = 110546454747203504006925729538023265156225304520988132722771250047696607274399
q = 69432444660353724912594441619180565122596810625659229683919790847518915561813
N = (p**3 - p)*(q**3 - q)
phi = 8130718311181529512023061937820198911824250577656859808220234200906934536574593002998439406567360340616588872082761396586369901175200281306229826359367416808716672544100675100778004339594396045911708929205724269740521522382094059853335398782101368420506241771196284270924708276195859621696139078700006880839569915571277371872103794764324997362673688435622070419864110256852465372308815637409824647991609263674448439608843405825808056538999591789771495781171200

def ExtendedEuclidAlgo(a, b):
    if a == 0 :
        return b, 0, 1
    gcd, x1, y1 = ExtendedEuclidAlgo(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def linearCongruence(A, B, N):
    A, B = A % N, B % N
    u, v = 0, 0
    d, u, v = ExtendedEuclidAlgo(A, N)

    res = []
    if (B % d != 0):
        return res

    x0 = (u * (B // d)) % N
    if x0 < 0:
        x0 += N
    for i in range(d):
        res.append((x0 + i * (N // d)) % N)

    return res

def find_m(e, c):
    m_possible = []
    d = inverse(e, phi)
    ct = pow(c, d, N)

    for gcd in range(1, 100):
        if N % gcd:
            continue
        roots = linearCongruence(pow(gcd, e*d, N), ct, N)
        for x in roots:
            m_possible.append((x * gcd) % N)
    return m_possible

conn = remote("154.26.136.227", 46352)
conn.recvuntil("> ")
conn.sendline("1")
conn.recvuntil(": ")
conn.sendline(str(p) + ", " + str(q))


m1, m2, m3 = [], [], []
while True:
    conn.recvuntil("> ")
    conn.sendline("2")
    data = conn.recvline()
    e1 = data.decode().strip().split(" ")[0]
    c1 = data.decode().strip().split(" ")[1]
    e1, c1 = int(e1[1:-1]), int(c1[:-1])

    data = conn.recvline()
    e2 = data.decode().strip().split(" ")[0]
    c2 = data.decode().strip().split(" ")[1]
    e2, c2 = int(e2[1:-1]), int(c2[:-1])

    data = conn.recvline()
    e3 = data.decode().strip().split(" ")[0]
    c3 = data.decode().strip().split(" ")[1]
    e3, c3 = int(e3[1:-1]), int(c3[:-1])

    if GCD(e1, phi) == 1:
        m1 = find_m(e1, c1)
    if GCD(e2, phi) == 1:
        m2 = find_m(e2, c2)
    if GCD(e3, phi) == 1:
        m3 = find_m(e3, c3)

    m1 = list(set(m1))
    m2 = list(set(m2))
    m3 = list(set(m3))
    print(len(m1), len(m2), len(m3))
    if len(m1) and len(m2) and len(m3):
        for x1, x2, x3 in itertools.product(m1, m2, m3):
            x = ZZ['x'].gen()
            fx = x**3 - x2*x**2 + x3*x - x1
            root = fx.roots()
            if len(root) == 3:
                flag = b""
                flag += long_to_bytes(int(root[2][0]))
                flag += long_to_bytes(int(root[1][0]))
                flag += long_to_bytes(int(root[0][0]))

                print(flag)
                exit()


# Flag: W1{wi3rd_ch41!En9e_n33d_4_WlErD_s0O!luti0n_6f339749663eeb3508c3b00c15872e41}