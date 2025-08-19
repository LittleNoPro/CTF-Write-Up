state = [('', '')]

def calc(x, y):
    res = ""
    for a, b in zip(x, y):
        res += str(int(a) * int(b))
    return res

for i in range(7):
    new_state = []
    for x, y in state:
        for x_dig in range(10):
            for y_dig in range(10):
                nx = str(x_dig) + x
                ny = str(y_dig) + y

                st = calc(nx, ny)
                valxy = int(nx) * int(ny)

                if len(st) + 2 * (7 - i - 1) < 14:
                    continue

                if st[-(i + 1):] == str(valxy % (10 ** (i + 1))):
                    new_state.append((nx, ny))

    state = new_state

print(len(state))

from hashlib import sha256
from Crypto.Cipher import AES

def dream_multiply(x, y):
    x, y = str(x), str(y)
    assert len(x) == len(y) + 1
    digits = x[0]
    for a, b in zip(x[1:], y):
        digits += str(int(a) * int(b))
    return int(digits)

for x, y in state:
    for dig in range(1, 10, 1):
        nx = str(dig) + x
        nx, ny = int(nx), int (y)

        if dream_multiply(nx, ny) == nx * ny and nx * ny != 3_81_40_42_24_40_28_42:
            ct = '75bd1089b2248540e3406aa014dc2b5add4fb83ffdc54d09beb878bbb0d42717e9cc6114311767dd9f3b8b070b359a1ac2eb695cd31f435680ea885e85690f89'
            print(AES.new(sha256(str((nx, ny)).encode()).digest(), AES.MODE_ECB).decrypt(bytes.fromhex(ct)))

# SEKAI{iSOgenni_in_mY_D1234M5;_iS_it_T00_s00n}