#!/usr/bin/env python3

from hashlib import sha256
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flag import iflags, final_flag

TOTAL_BITS = 624 * 37
def challenge(num_bit, previous, current):
    random.seed(os.urandom(16))
    num_task = (TOTAL_BITS + num_bit - 1) // num_bit

    output = ""
    for _ in range(num_task):
        output += format(random.getrandbits(num_bit), f"0{num_bit}b")

    print(output)

    key = previous
    for _ in range(100):
        key += format(random.getrandbits(num_bit), f"0{num_bit}b").encode()
        key = sha256(key).digest()

    cipher = AES.new(key, AES.MODE_CBC, iv=b'iluvredblacktree')
    print(cipher.encrypt(pad(current, 16)).hex())

challenge(32, b'iloveredblacktree', iflags[0])
challenge(16, iflags[0], iflags[1])
challenge(8, iflags[1], iflags[2])
challenge(4, iflags[2], iflags[3])
challenge(2, iflags[3], iflags[4])
challenge(1, iflags[4], final_flag)