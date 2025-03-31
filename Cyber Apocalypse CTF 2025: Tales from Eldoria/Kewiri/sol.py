from pwn import *
from sage.all import *
from Crypto.Util.number import *

io = remote("94.237.51.67", 52365, level = 'debug')
io.recvuntil(b"You are given the sacred prime: p = ")
p = int(io.recvline())


""" QUESTION 1 """
io.sendafter(b"[1] How many bits is the prime p? > ", str(p.bit_length()).encode() + b"\n")





""" QUESTION 2 """
# p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
# prs = factor(p - 1)
# pr = [val[0] for val in prs]
# test2 = ""
# for p, e in prs:
#     test2 += str(p) + "," + str(e) + "_"
# test2 = test2[:-1]
answer2 = "2,2_5,1_635599,1_2533393,1_4122411947,1_175521834973,1_206740999513,1_1994957217983,1_215264178543783483824207,1_10254137552818335844980930258636403,1"
io.sendafter(b'[2] Enter the full factorization of the order of the multiplicative group in the finite field F_p in ascending order of factors (format: p0,e0_p1,e1_ ..., where pi are the distinct factors and ei the multiplicities of each factor) > ', answer2.encode() + b"\n")





""" QUESTION 3 """
def is_generator(g, p, factors):
    for prime in factors:
        if pow(g, (p - 1) // prime, p) == 1:
            return 0
    return 1

# p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
# pr = [val[0] for val in factor(p - 1)]
pr = [2, 5, 635599, 2533393, 4122411947, 175521834973, 206740999513, 1994957217983, 215264178543783483824207, 10254137552818335844980930258636403]

io.recvuntil(b'[3] For this question, you will have to send 1 if the element is a generator of the finite field F_p, otherwise 0.\n')
for _ in range(17):
    g = int(io.recvuntil(b"?").decode()[:-1])
    io.sendafter(b" > ", str(is_generator(g, p, pr)).encode() + b'\n')





""" QUESTION 4 """
# from sage.all import *
# a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
# b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
# p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
# E = EllipticCurve(GF(p, 'x'), [a, b])
# print(E.order())
ord_p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
io.sendafter(b"[4] What is the order of the curve defined over F_p? > ", str(ord_p).encode() + b'\n')





""" QUESTION 5 """
# from sage.all import *
# a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
# b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
# p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
# E = EllipticCurve(GF(p**3, 'x'), [a, b])
# ord_E = E.order()
# print(ord_E)
answer5 = "2,2_7,2_21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061,1_2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019,1"
io.sendafter(b'[5] Enter the full factorization of the order of the elliptic curve defined over the finite field F_{p^3}. Follow the same format as in question 2 > ', answer5.encode() + b'\n')





""" QUESTION 6 """
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
io.recvuntil(b"G has x-coordinate: ")
xG = int(io.recvline().strip().decode())
io.recvuntil(b"A has x-coordinate: ")
xA = int(io.recvline().strip().decode())

rhs_G = (xG**3 + a * xG + b) % p
yG = GF(p)(rhs_G).sqrt()

rhs_A = (xA**3 + a * xA + b) % p
yA = GF(p)(rhs_A).sqrt()

E = EllipticCurve(GF(p), [a, b])
G = E([xG, yG])
A = E([xA, yA])

assert p == E.order()

# https://ctftime.org/writeup/29702
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

d = SmartAttack(G, A, p)

io.sendafter(b"[6] What is the value of d? > ", str(d).encode() + b'\n')
io.recvall()


# # HTB{Welcome_to_CA_2k25!Here_is_your_anomalous_flag_for_this_challenge_and_good_luck_with_the_rest:)_bb963b691944fe78c2fff72e46569343}