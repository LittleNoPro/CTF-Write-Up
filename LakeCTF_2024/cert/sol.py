from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from binascii import hexlify, unhexlify

context.log_level = 'critical'

signature = 20661001899082038314677406680643845704517079727331364133442054045393583514677972720637608461085964711216045721340073161354294542882374724777349428076118583374204393298507730977308343378120231535513191849991112740159641542630971203726024554641972313611321807388512576263009358133517944367899713953992857054626

n = 0xb678170a2e2faf2a29d6b236a8508c4a27a828c5c9f40ad467768ef60af30eda4e8596e4cbc3919db6d104ea1155025052918fb8fb3ef78510c6ea41f5be60e26103fb0f36a71883a23027f544b08ad35fc328b184e83f8973695e339d75fe4565e90457f051ba327eb14d77d76fc60b8800e5d04d9407561dc708889ee8b001
e = 0x010001

message = "Sign \"admin\" for flag. Cheers, "
m = 147375778215096992303698953296971440676323238260974337233541805023476001824
assert bytes_to_long(message.encode()) == m

t = 418296719726
assert t == bytes_to_long("admin".encode())

from Crypto.Util.number import *
def attack_sig(m,e,n,s):
    return GCD(s**e - m,n)

q = GCD(signature**e - m, n)
p = n // q

d = inverse(e, (p-1)*(q-1))

s = pow(t, d, n)

io = remote('chall.polygl0ts.ch', 9024)
k = io.recvline()
io.sendlineafter(b" > ", long_to_bytes(s).hex().encode())
print(io.recvline().decode().strip())
io.close()
