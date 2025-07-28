import random
import hashlib
from pwn import *
from ast import *
from tqdm import *
from sage.all import *
from Crypto.Util.number import *
from fractions import Fraction
from randcrack import RandCrack
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# io = remote('host8.dreamhack.games', 20028, level='debug')
# io = process(['python3', '/home/team/CodePy/chal.py'], level='debug')

from Crypto.Cipher import AES
from collections import defaultdict

limit = 1000
rhs_dict = defaultdict(list)

for c in trange(1, limit):
    for d in trange(1, limit):
        rhs_dict[c**4 + d**4 + 17].append((c, d))

for a in trange(1, limit):
    for b in trange(1, limit):
        rhs = a**4 + b**4
        if rhs in rhs_dict:
            print('t')
            for c, d in rhs_dict[rhs]:
                print(f"a={a}, b={b}, c={c}, d={d}")
                key = str(a*b*c*d).zfill(16).encode()
                cipher = AES.new(key, AES.MODE_ECB)
                ct = bytes.fromhex('41593455378fed8c3bd344827a193bde7ec2044a3f7a3ca6fb77448e9de55155')
                print(f"key = {key.decode()}")
                print(f"plaintext = {cipher.decrypt(ct)}")
                exit()

# uiuctf{D1oPh4nTine__Destr0yer__}