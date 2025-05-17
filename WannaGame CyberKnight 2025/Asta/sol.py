f = 0x18bc6627317918a4fd88c72ea42acfaa1

def from_bytes(bs):
    return int.from_bytes(bs, byteorder="big")

def to_bytes(v):
    return int.to_bytes(v, 16, byteorder="big")

def red(x):
    while (l := x.bit_length()) > 128:
        x ^= f << (l - 129)
    return x

def mul(x, y):
    z = 0
    for i in range(x.bit_length()):
        if (x >> i) & 1:
            z ^= y << i
    return red(z)
def exp(x, n):
    assert n >= 0
    if not n:
        return 1
    if n % 2:
        return mul(x, exp(x, n-1))
    return exp(mul(x, x), n//2)

def padding(msg):
    l = len(msg)
    msg += b'\x80'
    msg += b'\0' * (16 - (len(msg)%16))
    msg += to_bytes(16 * l)
    return msg

def function(x, y):
    return to_bytes(exp(from_bytes(x + y), 1337))

def md128(msg):
    msg = padding(msg)
    print(msg)
    iv = to_bytes(0x1234567890abcdefdeadbeef1337dada)
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        state = function(iv, block)
        iv = state
    return state



from pwn import *
import json

io = remote("ctf.cnsc.com.vn", 32927, level="debug")
# io = process(["python3", "/home/team/CodePy/chall.py"], level="debug")
io.recvline()

data = {"action": "register", "username": "0"}
io.sendline(json.dumps(data).encode())
hashval = json.loads(io.recvline().decode())['hash']
hashval = bytes.fromhex(hashval)

for l in range(100):
    token = "0" * l + f'username=0||admin=False'
    token = padding(token.encode())

    tmp = token + b"admin=True"
    l1 = len(tmp)
    block = padding(tmp)
    l2 = len(block)
    res = block[l:-(l2-l1)]

    hash1 = function(hashval, block[-32:-16])
    hash2 = function(hash1, block[-16:])

    data = {"action": "login", "token": res.hex(), "hash": hash2.hex()}
    io.sendline(json.dumps(data).encode())
    flag = json.loads(io.recvline().decode())['msg']
    if 'W1' in flag:
        print(flag)
        break


