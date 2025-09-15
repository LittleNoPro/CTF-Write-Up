from sage.all import *
from Crypto.Util.number import *

p = 0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21
A = 5
B = 7
q = 457
Qx = 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5

F = GF(p)
E = EllipticCurve(F, [A, B])
Q = E.lift_x(F(Qx))

N = E.order()
assert N % q == 0
M = N // q

d_M = inverse_mod(q, M)
P0 = d_M * Q

S = E.random_point()
G_q = M * S

while G_q.is_zero():
    S = E.random_point()
    G_q = M * S

for k in range(q):
    P_k = P0 + k * G_q
    m = P_k.x()

    flag = long_to_bytes(int(m))

    if all(32 <= b < 127 for b in flag):
        print("ictf{", end='')
        print(f"{flag.decode()}", end='')
        print("}")
        break

# ictf{mayb3_d0nt_m4ke_th3_sca1ar_a_f4ctor_0f_the_ord3r}