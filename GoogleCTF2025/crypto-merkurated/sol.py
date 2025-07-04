import bcrypt
import hashlib
from ecdsa import SigningKey
from ecdsa.ecdsa import Signature
from ecdsa.curves import NIST256p
from pwn import *
from tqdm import trange
import subprocess
import re
import tempfile
import os
import json
import random

# sk = SigningKey.generate(curve=NIST256p)
# vk = sk.get_verifying_key()
# pk = vk.pubkey.point.x()

sk = '575156a1806cef06d1224c89dbafebfc1bb828fd35ca82c18b23d369875c3aa7'
sk = SigningKey.from_string(bytes.fromhex(sk), curve=NIST256p)
pk = 28300330634304417691698698855204040081570122261197191457707776099491314287830

def sign(message):
    message_hash = hashlib.sha256(message).digest()
    signature = sk.sign_digest(
        message_hash,
        sigencode=lambda r, s, order: (int(r).to_bytes(32, 'big') + int(s).to_bytes(32, 'big'))
    )
    return signature + bytes([0])





io = remote("merkurated.2025.ctfcompetition.com", 1337, level='debug')

pow_prompt = io.recvuntil(b"Solution?").decode()
challenge_id = re.search(r"solve (s\.[^\s]+)", pow_prompt).group(1)
with tempfile.NamedTemporaryFile("w+", delete=False) as tmpf:
    tmpf.write(subprocess.check_output(["curl", "-sSL", "https://goo.gle/kctf-pow"]).decode())
    tmpf.flush()
    pow_script_path = tmpf.name
solution = subprocess.check_output(["python3", pow_script_path, "solve", challenge_id]).strip()
io.sendline(solution)
io.recvline()


SALT_FOR_NODE = io.recvline().split(b' ')[-1].strip()
SALT_FOR_VALUE = io.recvline().split(b' ')[-1].strip()

def hash(message, salt):
    h = bcrypt.hashpw(message, salt)
    _salt, h = h[:29], h[29:]
    assert salt == _salt
    return h

EMPTY_NODE_HASH  = hash(b'', SALT_FOR_NODE)
EMPTY_VALUE_HASH = hash(b'', SALT_FOR_VALUE)



dic = {}
for _ in range(2**20):
    INVALID_VALUE = random.randrange(10**18, 2**64)
    VALID_VALUE = random.randrange(0, 10**9)

    if hash(int.to_bytes(INVALID_VALUE, 8, 'big'), SALT_FOR_VALUE)[:4] in dic.values():
        VALID_VALUE = list(dic.keys())[list(dic.values()).index(hash(int.to_bytes(INVALID_VALUE, 8, 'big'), SALT_FOR_VALUE)[:4])]
        print(f'Found collision: {INVALID_VALUE} -> {VALID_VALUE}')
        break

    dic[VALID_VALUE] = hash(int.to_bytes(VALID_VALUE, 8, 'big'), SALT_FOR_VALUE)[:4]


# diposit
amount = VALID_VALUE
public_key = bytes.fromhex(hex(pk)[2:])

io.sendlineafter(f'🤖 '.encode(), f'deposit {amount} {public_key.hex()}'.encode())


# withdraw
amount = INVALID_VALUE
proof = amount.to_bytes(8, 'big')
for _ in range(256):
    proof += EMPTY_NODE_HASH
signature = sign(proof)

io.sendlineafter(f'🤖 '.encode(), f'withdraw {amount} {signature.hex()} {proof.hex()}'.encode())


# flag
io.sendlineafter(f'🤖 '.encode(), f'flag'.encode())
io.recvuntil(f'🏁 ')
flag = io.recvline().strip().decode()
print(f'Flag: {flag}')

#  CTF{bcryp7_h4sh_c0l11s10n_1s_tr1via1_by_d351gn}