import random
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES

ticket = random.getrandbits(128)
FLAG = ""
with open('flag.txt', 'r') as flag:
    FLAG = flag.read()

p = getPrime(1024)
q = getPrime(1024)
N = p * q
phi = (p - 1) * (q - 1)

e = getPrime(16) + (random.getrandbits(128) * phi)
enc_ticket = pow(ticket, e, N)

print(f"{N=}")
print(f"{e=}")
print(f"{enc_ticket=}")

cipher = AES.new(long_to_bytes(ticket), AES.MODE_CTR)
nonce = cipher.nonce
enc_flag = cipher.encrypt(FLAG.encode())

print(f"{enc_flag, nonce=}")
