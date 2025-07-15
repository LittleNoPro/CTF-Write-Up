from z3 import *

MASK64 = (1 << 64) - 1

def rotl(x, k):
    return ((x << k) | LShR(x, 64 - k)) & MASK64

leaks = [0x785a1cb672480875, 0x91c1748fec1dd008, 0x5c52ec3a5931f942, 0xac4a414750cd93d7]

s0 = BitVec('s0', 64)
s1 = BitVec('s1', 64)
s2 = BitVec('s2', 64)
s3 = BitVec('s3', 64)

def next_raw(state):
    s0, s1, s2, s3 = state
    t = (s1 << 17) & MASK64

    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = rotl(s3, 45)

    return s1, [s0, s1, s2, s3]

solver = Solver()
state = [s0, s1, s2, s3]

for i in range(4):
    out, state = next_raw(state)
    solver.add(out == leaks[i])

if solver.check() == sat:
    model = solver.model()
    recovered = [model[v].as_long() for v in [s0, s1, s2, s3]]
    print("Found state:", recovered)

from secrets import randbits
from prng import xorshiro256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ecc import ECDSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import *
import hashlib

state = [4632343889369999961, 10793220881798324403, 12527397580889080479, 11809022490152434257]
prng = xorshiro256(state)
leaks = [prng.next_raw() for _ in range(4)]
print(f"PRNG leaks: {[hex(x) for x in leaks]}")
k = prng()
r, s = (54809455810753652852551513610089439557885757561953942958061085530360106094036, 42603888460883531054964904523904896098962762092412438324944171394799397690539)
h = 9529442011748664341738996529750340456157809966093480864347661556347262857832209689182090159309916943522134394915152900655982067042469766622239675961581701969877932734729317939525310618663767439074719450934795911313281256406574646718593855471365539861693353445695
d = inverse(r, ECDSA.n) * (s * k - h) % ECDSA.n

key = hashlib.sha256(long_to_bytes(d)).digest()
ciphertext = '404e9a7bbdac8d3912d881914ab2bdb924d85338fbd1a6d62a88d793b4b9438400489766e8e9fb157c961075ad4421fc'
iv = bytes.fromhex(ciphertext[:32])
ciphertext = bytes.fromhex(ciphertext[32:])
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ciphertext)
print(flag)

# L3AK{u_4r3_th3_sh1r0_h3r0!}