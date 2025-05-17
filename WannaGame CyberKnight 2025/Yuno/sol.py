from sage.all import *
from pwn import *
from Crypto.Util.number import *
from md128 import *

f = 0x18bc6627317918a4fd88c72ea42acfaa1  # modulus
x = GF(2)["x"].gen()
F = GF(2**128, name="y", modulus=x**128 + x**127 + x**123 + x**121 + x**120 + x**119 + x**118 + x**114 + x**113 + x**110 + x**109 + x**105 + x**102 + x**101 + x**100 + x**97 + x**96 + x**92 + x**90 + x**89 + x**88 + x**87 + x**84 + x**80 + x**79 + x**75 + x**73 + x**70 + x**67 + x**66 + x**65 + x**64 + x**63 + x**62 + x**60 + x**59 + x**55 + x**51 + x**50 + x**46 + x**45 + x**44 + x**41 + x**39 + x**38 + x**37 + x**35 + x**33 + x**30 + x**25 + x**23 + x**21 + x**19 + x**18 + x**15 + x**14 + x**13 + x**12 + x**11 + x**9 + x**7 + x**5 + 1)
x = F.gen()

def int2field(n: int):
    return F(GF(2)['x']([(n >> i) & 1 for i in range(128)]))

def field2int(f):
    return f.to_integer()

io = remote("ctf.cnsc.com.vn", 32965, level = 'debug')
target = int2field(bytes_to_long(bytes.fromhex(io.recvline().decode())))

padding1 = int2field(bytes_to_long(b'\x80' + b'\x00' * 15))
padding2 = int2field(bytes_to_long(to_bytes(16 * 16)))

iv = int2field(0x1234567890abcdefdeadbeef1337dada)
tmp = (target.nth_root(1337) - padding2) / x**128
tmp = (tmp.nth_root(1337) - padding1) / x**128
tmp = tmp.nth_root(1337) - iv * x**128

plaintext = long_to_bytes(field2int(tmp))

io.sendline(plaintext.hex())
io.recvline()
