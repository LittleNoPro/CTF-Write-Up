from pwn import *
from math import gcd
from Crypto.Util.number import *

# conn = remote("verbal-sleep.picoctf.net", 55822, level = 'debug')

# Ns, es, cyphers = [], [], []
# N = conn.recvline().decode().strip().split(": ")[1]
# e = conn.recvline().decode().strip().split(": ")[1]
# cypher = conn.recvline().decode().strip().split(": ")[1]
# conn.close()

# Ns.append(N)
# es.append(e)
# cyphers.append(cypher)

# for _ in range(10):
#     conn = remote("verbal-sleep.picoctf.net", 55822, level = 'debug')

#     N = conn.recvline().decode().strip().split(": ")[1]
#     e = conn.recvline().decode().strip().split(": ")[1]
#     cypher = conn.recvline().decode().strip().split(": ")[1]

#     if gcd(int(N), int(Ns[-1])) != 1:
#         Ns.append(N)
#         es.append(e)
#         cyphers.append(cypher)

#         p = gcd(int(N), int(Ns[-1]))
#         N = int(N)
#         q = N // p
#         phi = (p - 1) * (q - 1)
#         d = inverse(int(e), phi)
#         flag = pow(int(cypher), d, N)
#         print(long_to_bytes(flag))
#         print("!!!!!")
#         exit()

#     conn.close()


N = 17456294557660845439073680326944189775704683839550119755153383785270236263530893465668197707588646253482442020488295976235547736623509858316535533481955518
e = 65537
ct = 12686342184280812597437137499139118509790050606327720438995975159007133131525970138776590302756820607856947498338733685865555398180155503828390502627613937
p = 2
q = N // p
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
flag = pow(ct, d, N)
print(long_to_bytes(flag))