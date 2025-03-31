from pwn import *
from tqdm import tqdm
from Crypto.Util.number import *
from sage.all import *

io = remote("94.237.51.14", 55839)
# io = process(["python3", "/home/team/CodePy/Cyber Apocalypse CTF 2025: Tales from Eldoria/Twin Oracles/server.py"])

FLAG = io.recvline().decode()

io.recvuntil(b"M = ")
M = int(io.recvline().strip().decode())

io.sendafter(b"> ", b"1\n")
io.recvuntil(b"n = ")
n = int(io.recvline().strip().decode())
io.recvuntil(b"The ancient script has been sealed: ")
c = int(io.recvline().strip().decode())
e = 65537

def oracle(num):
    io.sendafter(b"> ", b"2\n")
    io.sendafter(b"Submit your encrypted scripture for the Seers' judgement: ", hex(num).encode() + b'\n')
    io.recvuntil(b"The Seers whisper their answer: ")
    return io.recvline().strip().decode()


#  Find x0
number_question_for_x0 = 15
bits = ""
for i in tqdm(range(number_question_for_x0)):
    ok = oracle(pow(n - 1, e, n))
    bits += ok

X0 = 0
for x0 in range((1 << 14), (1 << 15)):
    if not isPrime(x0):
        continue

    x, ok = x0, True
    for i in range(number_question_for_x0):
        x = pow(x, 2, M)
        if int(x % 2) != int(bits[i]):
            ok = False
            break
    if ok:
        X0 = x0
        break


bits, x0 = "", X0
for i in range(1500):
    x0 = pow(x0, 2, M)
    bits += str(x0 % 2)
bits = bits[number_question_for_x0:]



high = ZZ(n)
low = ZZ(0)
i0, i1 = 0, 1
for j in tqdm(range(len(bits))):
    bit = bits[j]

    if bit == '1':
        output = oracle(c * pow(2**i0, e, n) % n)
    else:
        output = oracle(c * pow(2**i1, e, n) % n)

    if output == "0":
        high = (low + high) / 2
    else:
        low = (low + high) / 2

    i0 += 1
    i1 += 1

high = int(high)
print(high)
print(long_to_bytes(high))


# HTB{1_l0v3_us1ng_RS4_0r4cl3s___3v3n_4_s1ngl3_b1t_1s_3n0ugh_t0_g3t_m3_t0_3ld0r14!_6233599df7b453a9a1080c73e1b9f12b}