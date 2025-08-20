class Twister:
    N = 624
    M = 397
    A = 0x9908b0df

    def __init__(self):
        self.state = [ [ (1 << (32 * i + (31 - j))) for j in range(32) ] for i in range(624)]
        self.index = 0

    @staticmethod
    def _xor(a, b):
        return [x ^ y for x, y in zip(a, b)]

    @staticmethod
    def _and(a, x):
        return [ v if (x >> (31 - i)) & 1 else 0 for i, v in enumerate(a) ]

    @staticmethod
    def _shiftr(a, x):
        return [0] * x + a[:-x]

    @staticmethod
    def _shiftl(a, x):
        return a[x:] + [0] * x

    def get32bits(self):
        if self.index >= self.N:
            for kk in range(self.N):
                y = self.state[kk][:1] + self.state[(kk + 1) % self.N][1:]
                z = [ y[-1] if (self.A >> (31 - i)) & 1 else 0 for i in range(32) ]
                self.state[kk] = self._xor(self.state[(kk + self.M) % self.N], self._shiftr(y, 1))
                self.state[kk] = self._xor(self.state[kk], z)
            self.index = 0

        y = self.state[self.index]
        y = self._xor(y, self._shiftr(y, 11))
        y = self._xor(y, self._and(self._shiftl(y, 7), 0x9d2c5680))
        y = self._xor(y, self._and(self._shiftl(y, 15), 0xefc60000))
        y = self._xor(y, self._shiftr(y, 18))
        self.index += 1

        return y

    def getrandbits(self, bit):
        return self.get32bits()[:bit]

class Solver:
    def __init__(self):
        self.equations = []
        self.outputs = []

    def insert(self, equation, output):
        for eq, o in zip(self.equations, self.outputs):
            lsb = eq & -eq
            if equation & lsb:
                equation ^= eq
                output ^= o

        if equation == 0:
            return

        lsb = equation & -equation
        for i in range(len(self.equations)):
            if self.equations[i] & lsb:
                self.equations[i] ^= equation
                self.outputs[i] ^= output

        self.equations.append(equation)
        self.outputs.append(output)

    def solve(self):
        num = 0
        for i, eq in enumerate(self.equations):
            if self.outputs[i]:
                # Assume every free variable is 0
                num |= eq & -eq

        state = [ (num >> (32 * i)) & 0xFFFFFFFF for i in range(624) ]
        return state

import random
from Crypto.Util.number import *
from pyrandcracker import RandCracker
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

data, cts = [], []
with open('/home/team/CodePy/data.txt', 'r') as file:
    lines = file.readlines()
    for i in range(len(lines)):
        if i % 2 == 0:
            data.append(lines[i].strip())
        else:
            cts.append(lines[i].strip())

TOTAL_BITS = 624 * 37
num_bit = [32, 16, 8, 4, 2, 1]
previous = b'iloveredblacktree'

for round in range(6):
    print(f"\n[+] Solving round {round + 1} with {num_bit[round]} bits")

    outputs = [int(data[round][i:i + num_bit[round]], 2)
            for i in range(0, len(data[round]), num_bit[round])]

    twister = Twister()
    equations = [twister.getrandbits(num_bit[round]) for _ in range(len(outputs))]

    solver = Solver()
    for i in range(len(outputs)):
        for j in range(num_bit[round]):
            solver.insert(equations[i][j], (outputs[i] >> (num_bit[round] - 1 - j)) & 1)

    print("[+] Solving ....")

    state = solver.solve()
    recovered_state = (3, tuple(state + [0]), None)
    random.setstate(recovered_state)

    print("[+] Done ~~~")

    for i in range(len(outputs)):
        assert outputs[i] == random.getrandbits(num_bit[round])

    key = previous
    for _ in range(100):
        val = random.getrandbits(num_bit[round])
        key += format(val, f"0{num_bit[round]}b").encode()
        key = sha256(key).digest()

    ct = bytes.fromhex(cts[round])
    cipher = AES.new(key, AES.MODE_CBC, iv=b'iluvredblacktree')
    previous = cipher.decrypt(ct)
    previous = unpad(previous, 16)

    print(f"[+] Round {round + 1} plaintext: {previous}")

