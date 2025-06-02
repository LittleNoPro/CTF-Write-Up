from pwn import *
from tqdm import *

def XOR(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

io = remote("challs.nusgreyhats.org", 33302)
# io = process(["python3", "/home/team/CodePy/dist-shaker/shaker.py"], level='debug')

def See_inside():
    io.sendlineafter(b'> ', b'2')
    io.recvuntil(b'Result: ')
    ret = io.recvline().strip().decode()
    return bytes.fromhex(ret)

flag_enc = See_inside()
x = XOR(flag_enc, b"grey{")

# characters = set()
# for _ in trange(500):
#     ret = See_inside()
#     for ch in XOR(ret, x):
#         characters.add(bytes([ch]))

characters = {b'r', b'z', b'4', b'1', b'k', b'3', b'{', b'6', b'n', b'}', b'7', b'c', b'2', b'a', b'l', b'h', b'b', b'_', b't', b'i', b'v', b'd', b'e', b'f', b'0', b'q', b'o', b'u', b'g', b'w', b'5', b'y'}
print(characters)

for l in range(64):
    possible = []

    for ch in trange(256):
        ch = bytes([ch])
        ok = True

        for _ in range(200):
            ret = See_inside()

            if xor(ch, ret[len(x)]) not in characters:
                ok = False
                break

        if ok:
            possible.append(ch)
            break

    print(possible)
    for ch in possible:
        _x = x + ch
        cur = XOR(flag_enc, _x)
        if bytes([cur[-1]]) in characters:
            x += ch
            print(f"Found character: {ch}")
            break
    print(XOR(flag_enc, x))


# Flag: grey{kinda_long_flag_but_whatever_65k2n427c61ww064ac3vhzigae2qg}