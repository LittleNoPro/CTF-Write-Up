from sage.all import *
from Crypto.Util.number import *
from itertools import *

P = (103905521866731574234430443362297034336, 116589269353056499566212456950780999584)
U = (171660318017081135625337806416866746485, 122407097490400018041253306369079974706)
Q = (161940138185633513360673631821653803879, 167867902631659599239485617419980253311)
V = (95406403280474692216804281695624776780, 109560844064302254814641159241201048462)

points = [P, U, Q, V]
A = [point[1]**2 - point[0]**3 for point in points]
res = []
for i, j, k, l in permutations([0, 1, 2, 3]):
    res.append((A[i] - A[j]) * (points[k][0] - points[l][0]) - (A[k] - A[l]) * (points[i][0] - points[j][0]))
p = gcd(res)

a = (P[1]**2 - Q[1]**2 - (P[0]**3 - Q[0]**3)) * pow(P[0] - Q[0], -1, p) % p
b = (P[1]**2 - P[0]**3 - a*P[0]) % p

E = EllipticCurve(GF(p), [a, b])
P, U, Q, V = [E(point) for point in points]

assert P.order() == p and Q.order() == p

def _lift(E, P, gf):
    x, y = map(ZZ, P.xy())
    for point_ in E.lift_x(x, all=True):
        _, y_ = map(gf, point_.xy())
        if y == y_:
            return point_
def attack(G, P):
    E = G.curve()
    gf = E.base_ring()
    p = gf.order()
    assert E.trace_of_frobenius() == 1, f"Curve should have trace of Frobenius = 1."

    E = EllipticCurve(Qp(p), [int(a) + p * ZZ.random_element(1, p) for a in E.a_invariants()])
    G = p * _lift(E, G, gf)
    P = p * _lift(E, P, gf)
    Gx, Gy = G.xy()
    Px, Py = P.xy()
    return int(gf((Px / Py) / (Gx / Gy)))

nA = attack(P, U)
nB = attack(Q, V)

print(long_to_bytes(nA).decode(), long_to_bytes(nB).decode())

# L3AK{5m4rt1_1n_ Th3_h00000d!!!}